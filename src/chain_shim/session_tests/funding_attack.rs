// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! The third review's F1 on regtest: a real bitcoind, real BIP158 filters from it, two real nodes
//! and a real `funding_created` naming an output the opener merely controls. Nothing on the chain
//! ties that output to the channel script it pairs it with, so that pair proves nothing.

use std::str::FromStr;

use bitcoin::bip158::{BlockFilter, BlockFilterWriter, FilterHeader};
use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::hashes::Hash;
use bitcoin::{Address, Amount, Block, BlockHash, OutPoint, ScriptBuf, Transaction, Txid};
use electrsd::corepc_node::{self, Client, Node as BitcoinD};
use lightning::ln::msgs::SocketAddress;

use super::*;
use crate::funding::{FundingRequest, FundingSource};
use crate::types::ChannelManager;
use node_chain::session::machine::ConflictState;

fn bitcoind() -> BitcoinD {
	let exe = std::env::var("BITCOIND_EXE")
		.ok()
		.or_else(|| corepc_node::downloaded_exe_path().ok())
		.expect("BITCOIND_EXE or a bitcoind version feature");
	let mut conf = corepc_node::Conf::default();
	conf.network = "regtest";
	conf.args.push("-blockfilterindex=1");
	BitcoinD::with_conf(exe, &conf).unwrap()
}

/// What an honest Pro serves: bitcoind's own answers, filters and all.
struct BitcoindFilters(Arc<Client>);

impl BitcoindFilters {
	fn call(
		&self, method: &str, args: &[serde_json::Value],
	) -> Result<serde_json::Value, SourceError> {
		self.0.call(method, args).map_err(|e| SourceError::unavailable(e.to_string()))
	}
	fn hash_at(&self, height: u32) -> Result<BlockHash, SourceError> {
		let hash = self.call("getblockhash", &[height.into()])?;
		BlockHash::from_str(hash.as_str().unwrap_or_default())
			.map_err(|e| SourceError::unavailable(e.to_string()))
	}
	fn height_of(&self, hash: BlockHash) -> Result<u32, SourceError> {
		let header = self.call("getblockheader", &[hash.to_string().into()])?;
		Ok(header["height"].as_u64().unwrap_or_default() as u32)
	}
	fn filter_at(&self, height: u32) -> Result<(BlockFilter, FilterHeader), SourceError> {
		let hash = self.hash_at(height)?;
		let answer = self.call("getblockfilter", &[hash.to_string().into()])?;
		let content: Vec<u8> =
			bitcoin::hex::FromHex::from_hex(answer["filter"].as_str().unwrap()).unwrap();
		let header = FilterHeader::from_str(answer["header"].as_str().unwrap()).unwrap();
		Ok((BlockFilter::new(&content), header))
	}
}

#[async_trait]
impl FilterSource for BitcoindFilters {
	fn name(&self) -> &'static str {
		"bitcoind"
	}
	async fn tip(&self) -> Result<BlockId, SourceError> {
		let height = self.call("getblockcount", &[])?.as_u64().unwrap_or_default() as u32;
		Ok(BlockId { height, hash: self.hash_at(height)? })
	}
	async fn headers(&self, from_height: u32, count: u32) -> Result<Vec<Header>, SourceError> {
		let mut out = Vec::new();
		for height in from_height..from_height + count {
			let Ok(hash) = self.hash_at(height) else { break };
			let raw = self.call("getblockheader", &[hash.to_string().into(), false.into()])?;
			out.push(deserialize_hex(raw.as_str().unwrap()).unwrap());
		}
		if out.is_empty() {
			return Err(SourceError::NotFound("above tip".into()));
		}
		Ok(out)
	}
	async fn filter_headers(
		&self, start_height: u32, stop_hash: BlockHash,
	) -> Result<FilterHeaders, SourceError> {
		let stop = self.height_of(stop_hash)?;
		let previous = match start_height {
			0 => FilterHeader::all_zeros(),
			height => self.filter_at(height - 1)?.1,
		};
		let mut headers = Vec::new();
		for height in start_height..=stop {
			headers.push(self.filter_at(height)?.1);
		}
		Ok(FilterHeaders { previous, headers })
	}
	async fn filters(
		&self, start_height: u32, stop_hash: BlockHash,
	) -> Result<Vec<IndexedFilter>, SourceError> {
		let stop = self.height_of(stop_hash)?;
		let mut out = Vec::new();
		for height in start_height..=stop {
			let filter = self.filter_at(height)?.0;
			out.push(IndexedFilter { height, block_hash: self.hash_at(height)?, filter });
		}
		Ok(out)
	}
	async fn block(&self, hash: BlockHash) -> Result<Block, SourceError> {
		let raw = self.call("getblock", &[hash.to_string().into(), 0.into()])?;
		Ok(deserialize_hex(raw.as_str().unwrap()).unwrap())
	}
}

/// bitcoind's answers, with one filter swapped for one of the attacker's making, and the filter
/// headers above it following from that: a chain that holds together.
struct ForgedAt {
	honest: Arc<BitcoindFilters>,
	forged: Mutex<Option<(u32, BlockFilter)>>,
}

#[async_trait]
impl FilterSource for ForgedAt {
	fn name(&self) -> &'static str {
		"forged"
	}
	async fn tip(&self) -> Result<BlockId, SourceError> {
		self.honest.tip().await
	}
	async fn headers(&self, from_height: u32, count: u32) -> Result<Vec<Header>, SourceError> {
		self.honest.headers(from_height, count).await
	}
	async fn filter_headers(
		&self, start_height: u32, stop_hash: BlockHash,
	) -> Result<FilterHeaders, SourceError> {
		let forged = self.forged.lock().unwrap().clone();
		let Some((at, filter)) = forged else {
			return self.honest.filter_headers(start_height, stop_hash).await;
		};
		let stop = self.honest.height_of(stop_hash)?;
		if stop < at {
			return self.honest.filter_headers(start_height, stop_hash).await;
		}
		let mut running = self.honest.filter_at(at - 1)?.1;
		let mut said = Vec::new();
		for height in at..=stop {
			let this = if height == at { filter.clone() } else { self.honest.filter_at(height)?.0 };
			running = this.filter_header(&running);
			said.push((height, running));
		}
		let of = |height: u32| said.iter().find(|(h, _)| *h == height).map(|(_, fh)| *fh);
		let previous = match start_height.checked_sub(1) {
			None => FilterHeader::all_zeros(),
			Some(below) if below >= at => of(below).unwrap(),
			Some(below) => self.honest.filter_at(below)?.1,
		};
		let mut headers = Vec::new();
		for height in start_height..=stop {
			headers.push(match of(height) {
				Some(forged) => forged,
				None => self.honest.filter_at(height)?.1,
			});
		}
		Ok(FilterHeaders { previous, headers })
	}
	async fn filters(
		&self, start_height: u32, stop_hash: BlockHash,
	) -> Result<Vec<IndexedFilter>, SourceError> {
		let mut out = self.honest.filters(start_height, stop_hash).await?;
		if let Some((at, filter)) = self.forged.lock().unwrap().clone() {
			if let Some(row) = out.iter_mut().find(|row| row.height == at) {
				row.filter = filter;
			}
		}
		Ok(out)
	}
	async fn block(&self, hash: BlockHash) -> Result<Block, SourceError> {
		self.honest.block(hash).await
	}
}

struct Pros(HashMap<String, Arc<dyn FilterSource>>, Arc<TestPro>);

impl ProviderConnector for Pros {
	fn connect(&self, node_id: &str) -> ProviderEndpoints {
		let filters = Arc::clone(self.0.get(node_id).expect("a Pro of this test"));
		ProviderEndpoints {
			chain: Arc::new(Chain(Arc::clone(&self.1))),
			bundles: Arc::new(ServerTransport::new(Arc::clone(&filters))),
			filters,
		}
	}
}

/// Opens a channel and names `output` as its funding, whatever that output pays: LDK's
/// `unsafe_manual_funding_transaction_generated`, or anyone's own software on the wire. Keeps the
/// script the victim will pair with it.
struct NamesAnOutput {
	manager: Arc<ChannelManager>,
	output: OutPoint,
	script: Mutex<Option<ScriptBuf>>,
}

impl FundingSource for NamesAnOutput {
	fn create_funding_transaction(&self, req: FundingRequest) -> Result<Transaction, Error> {
		*self.script.lock().unwrap() = Some(req.output_script.clone());
		let txo = lightning::chain::transaction::OutPoint {
			txid: self.output.txid,
			index: self.output.vout as u16,
		};
		self.manager
			.unsafe_manual_funding_transaction_generated(
				req.temporary_channel_id,
				req.counterparty_node_id,
				txo,
			)
			.expect("LDK takes the outpoint as it is");
		// Past this the open is LDK's. LDK refuses what this hands back, and the node forgets its own
		// side of the open.
		Ok(Transaction {
			version: bitcoin::transaction::Version::TWO,
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: Vec::new(),
			output: Vec::new(),
		})
	}
	fn release(&self, _: lightning::ln::types::ChannelId) {}
}

fn pay(client: &Client, to: &Address, sats: u64) -> OutPoint {
	let txid: String = client
		.call("sendtoaddress", &[to.to_string().into(), Amount::from_sat(sats).to_btc().into()])
		.unwrap();
	let txid = Txid::from_str(&txid).unwrap();
	let raw: String = client.call("getrawtransaction", &[txid.to_string().into()]).unwrap();
	let tx: Transaction = deserialize_hex(&raw).unwrap();
	let vout = tx.output.iter().position(|out| out.script_pubkey == to.script_pubkey()).unwrap();
	OutPoint { txid, vout: vout as u32 }
}

/// Spends `output`, which bitcoind's wallet controls, in an ordinary transaction.
fn spend(client: &Client, output: OutPoint, sats: u64, to: &Address) -> Txid {
	let inputs = serde_json::json!([{ "txid": output.txid.to_string(), "vout": output.vout }]);
	let outputs = serde_json::json!([{ to.to_string(): Amount::from_sat(sats - 1_000).to_btc() }]);
	let raw: String = client.call("createrawtransaction", &[inputs, outputs]).unwrap();
	let signed: serde_json::Value =
		client.call("signrawtransactionwithwallet", &[raw.into()]).unwrap();
	let txid: String = client
		.call("sendrawtransaction", &[signed["hex"].clone(), 0.into()])
		.expect("the spend goes in");
	Txid::from_str(&txid).unwrap()
}

fn listening_node(session: Arc<ChainProviderSession>, dir: &Path, seed: u8, port: u16) -> Stack {
	let mut host_builder = ChainHostBuilder::new(Network::Regtest);
	host_builder.set_logger(logger());
	host_builder.set_chain_source_cbf_with_session(
		Vec::new(),
		CbfConfig { source: CbfSource::Node, ..CbfConfig::default() },
		session,
	);
	let host = host_builder.build().expect("a host");
	let mut builder = Builder::new();
	builder.set_network(Network::Regtest);
	builder.set_log_facade_logger();
	builder.set_storage_dir_path(dir.to_str().unwrap().to_string());
	builder.set_entropy_seed_bytes([seed; 64]);
	builder.set_chain_host(Arc::clone(&host));
	builder
		.set_listening_addresses(vec![
			SocketAddress::from_str(&format!("127.0.0.1:{}", port)).unwrap()
		])
		.unwrap();
	let node = builder.build_with_store(Arc::new(TestStore::new(false))).expect("a node builds");
	let runtime =
		Arc::new(tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap());
	node.start_with_runtime(Arc::clone(&runtime)).expect("a node starts");
	Stack { host, node, runtime }
}

fn wait_long(what: &str, check: impl Fn() -> bool) {
	let started = Instant::now();
	while !check() {
		assert!(started.elapsed() < Duration::from_secs(240), "timed out waiting for {}", what);
		std::thread::sleep(Duration::from_millis(100));
	}
}

fn free_port() -> u16 {
	std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Review 3's F1, all five steps, with the owner's pin on an honest Pro.
#[test]
fn a_stranger_naming_a_funding_output_cannot_convict_an_honest_pro() {
	let dir = temp_dir("funding-attack");
	let bitcoind = bitcoind();
	let rpc = bitcoind.params.rpc_socket;
	let cookie = bitcoind.params.get_cookie_values().unwrap().unwrap();
	let client = Arc::new(
		Client::new_with_auth(
			&bitcoind.rpc_url(),
			electrsd::corepc_node::client::client_sync::Auth::CookieFile(
				bitcoind.params.cookie_file.clone(),
			),
		)
		.unwrap(),
	);
	let ours = client.new_address().unwrap();
	client.generate_to_address(110, &ours).unwrap();

	// The Pros: an honest one the owner pinned, and the attacker's, free to tag itself one.
	let honest = Arc::new(BitcoindFilters(Arc::clone(&client)));
	let attacker_pro = Arc::new(ForgedAt { honest: Arc::clone(&honest), forged: Mutex::new(None) });
	let mut pros: HashMap<String, Arc<dyn FilterSource>> = HashMap::new();
	pros.insert(PRO_A.to_string(), Arc::clone(&honest) as Arc<dyn FilterSource>);
	pros.insert(PRO_B.to_string(), Arc::clone(&attacker_pro) as Arc<dyn FilterSource>);
	let quiet = TestPro::new(Arc::new(FakeSource::new(1, &[])), false);
	let session = ChainProviderSession::new(
		Arc::new(Pros(pros, quiet)),
		DeliveryPreference::Pull,
		Network::Regtest,
		dir.to_str().unwrap(),
		logger(),
	);
	session.set_auto_source(Some(false));
	session.set_source(Some(PRO_A.to_string()));

	// The victim, with some coins, as any node accepting channels has for its anchor reserve.
	let victim_port = free_port();
	let victim = listening_node(Arc::clone(&session), &dir, 61, victim_port);
	let victim_address = victim.node.onchain_payment().new_address().unwrap();
	pay(&client, &victim_address, 500_000);
	client.generate_to_address(1, &ours).unwrap();
	wait_long("the victim's coins", || victim.node.list_balances().total_onchain_balance_sats > 0);

	// Step 1 and 2: an output the attacker controls, named in `funding_created`. No funding.
	let attacker_dir = temp_dir("funding-attack-opener");
	let mut opener_builder = Builder::new();
	opener_builder.set_network(Network::Regtest);
	opener_builder.set_log_facade_logger();
	opener_builder.set_storage_dir_path(attacker_dir.to_str().unwrap().to_string());
	opener_builder.set_entropy_seed_bytes([62; 64]);
	opener_builder.set_chain_source_bitcoind_rpc(
		rpc.ip().to_string(),
		rpc.port(),
		cookie.user.clone(),
		cookie.password.clone(),
	);
	let opener = opener_builder.build_with_store(Arc::new(TestStore::new(false))).unwrap();
	let opener_runtime =
		Arc::new(tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap());
	opener.start_with_runtime(Arc::clone(&opener_runtime)).unwrap();
	let opener_address = opener.onchain_payment().new_address().unwrap();
	pay(&client, &opener_address, 500_000);
	let any_utxo = pay(&client, &ours, 200_000);
	client.generate_to_address(1, &ours).unwrap();
	let tip_now = client.get_block_count().unwrap().0 as u32;
	wait_long("the opener to catch up", || {
		opener.sync_wallets().ok();
		opener.status().current_best_block.height >= tip_now
			&& opener.list_balances().total_onchain_balance_sats > 0
	});
	wait_long("the victim to catch up", || {
		victim.node.status().current_best_block.height >= tip_now
	});
	let names = Arc::new(NamesAnOutput {
		manager: Arc::clone(&opener.channel_manager),
		output: any_utxo,
		script: Mutex::new(None),
	});
	let address = SocketAddress::from_str(&format!("127.0.0.1:{}", victim_port)).unwrap();
	opener
		.open_channel_with_funding(
			victim.node.node_id(),
			address,
			100_000,
			None,
			None,
			false,
			Arc::clone(&names) as Arc<dyn FundingSource>,
		)
		.unwrap();
	wait_long("the victim to hold the channel", || !victim.node.list_channels().is_empty());
	let channel = victim.node.list_channels().remove(0);
	assert_eq!(
		channel.funding_txo,
		Some(any_utxo),
		"the app's gates let it through: the victim pairs the named output with its channel script"
	);
	let script = names.script.lock().unwrap().clone().expect("what the victim pairs it with");

	// Step 3: it spends that output in an ordinary transaction. Honest filters for the block hold
	// the output's real script, not the channel's.
	spend(&client, any_utxo, 200_000, &ours);
	let at_block = client.generate_to_address(1, &ours).unwrap().0.remove(0);
	let at_block = BlockHash::from_str(&at_block).unwrap();
	let spent_height = client.get_block_count().unwrap().0 as u32;
	let (honest_filter, _) = honest.filter_at(spent_height).unwrap();
	let block: Block = client.get_block(at_block).unwrap();
	assert!(
		!honest_filter.match_any(&at_block, std::iter::once(script.as_bytes())).unwrap(),
		"the honest filter lacks the channel script"
	);

	// Step 4: at its turn as witness it serves a chain differing there, every real element and the
	// channel's script. It passes for hash and outputs.
	let real_prevout = ours.script_pubkey();
	let mut content = Vec::new();
	let mut writer = BlockFilterWriter::new(&mut content, &block);
	writer.add_output_scripts();
	writer.add_element(real_prevout.as_bytes());
	writer.add_element(script.as_bytes());
	writer.finish().unwrap();
	*attacker_pro.forged.lock().unwrap() = Some((spent_height, BlockFilter::new(&content)));
	client.generate_to_address(3, &ours).unwrap();
	let tip_now = client.get_block_count().unwrap().0 as u32;
	wait_long("the victim at the tip", || {
		victim.node.status().current_best_block.height >= tip_now
	});

	// Step 5: the check.
	session.set_candidates(vec![PRO_A.to_string(), PRO_B.to_string()]);
	session.check_soon();
	wait_long("the check at that block", || {
		let check = session.status().cross_check;
		check.last_witness.as_deref() == Some(PRO_B)
			&& check.last_result.as_deref() != Some("agreed")
	});

	let status = session.status();
	assert!(status.dropped.is_empty(), "the honest Pro is convicted: {:?}", status.dropped);
	assert!(!status.on_proven_liar);
	assert_eq!(status.active_node_id.as_deref(), Some(PRO_A));
	assert!(victim.node.check_chain_for_new_channel().is_ok(), "and new channels still open");
	let conflict = status.cross_check.conflict.expect("a difference, and nobody blamed");
	assert_eq!(conflict.height, spent_height);
	assert_ne!(conflict.state, ConflictState::SidesWithWitness);

	opener.stop().unwrap();
	victim.node.stop().unwrap();
	drop((opener_runtime, victim.runtime));
	std::fs::remove_dir_all(&dir).ok();
	std::fs::remove_dir_all(&attacker_dir).ok();
}
