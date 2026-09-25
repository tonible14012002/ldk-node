// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! [`BitcoindRpcSource`]: raw BIP157/158 data read from a bitcoind over
//! JSON-RPC — the Pro node's side of the filter source port.
//!
//! Separate from the bitcoind chain *source* in [`crate::chain::bitcoind`]:
//! that one follows the chain for this node's own wallet over LDK's RPC
//! client; this one only reads raw data for other nodes, over plain HTTP(S),
//! so it can sit behind a TLS-terminating proxy on another machine and does
//! not need to be this node's chain source at all.
//!
//! # What the bitcoind needs
//!
//! `getbestblockhash`, `getblockhash`, `getblockheader`, `getblock` and
//! `getblockfilter` — the last only with `-blockfilterindex=1`. Without the
//! index every filter call is [`SourceError::Unavailable`] with a reason that
//! says so; headers and blocks still work. A pruned node answers for blocks it
//! still has.
//!
//! # TLS
//!
//! `https://` URLs are checked against the web PKI roots, or — when a
//! certificate pin is given — against that pin alone: the SHA-256 of the
//! server's leaf certificate (DER), hex. Pinning is how a self-signed proxy
//! in front of the RPC port is trusted; the hostname is then not checked,
//! because the pin already names exactly one certificate. The handshake
//! signature is still verified, with the `ring` provider — the one
//! [`install_default_crypto_provider`] chooses — so no second crypto provider
//! is linked.
//!
//! [`install_default_crypto_provider`]: crate::chain::electrum
//!
//! # Time budget
//!
//! Every HTTP request carries its own timeout, sized to what it carries (see
//! the `RAW_RPC_*` constants). A serve call makes at most three requests in
//! sequence (resolve the span, fetch its hashes, fetch its data), except that
//! filter data is fetched in batches of [`FILTER_RPC_BATCH`]; the whole serve
//! call is therefore bounded by those budgets summed.
//!
//! A per-request timeout runs from the start of the connect until the body
//! has been read, so [`RAW_RPC_CONNECT_TIMEOUT_SECS`] sits inside it; the
//! table counts it on top anyway, as the conservative bound.
//!
//! Each route is relayed to a remote node as one unary peer call, and the
//! peer carrier (node-app-iroh) caps every outbound unary call at 60 s. So
//! per route: this source's budget < the host serve timeout < the client
//! wait < 60 s, each step with a margin:
//!
//! | route                     | per request here | host serve | client wait | carrier |
//! |---------------------------|------------------|------------|-------------|---------|
//! | `chain.block`             | 40 (+10) s       | 54 s       | 58 s        | 60 s    |
//! | `chain.filters`           | 30 (+10) s       | 45 s       | 50 s        | 60 s    |
//! | `chain.tip` / `headers` / `filter_headers` | 20 (+10) s | 35 s | 40 s  | 60 s    |
//!
//! `chain.block` is a single `getblock`, so its row is the whole serve call.
//! The other routes chain several requests; their typical total is well
//! under the host timeout, and a pathological one is cut by the host serve
//! timeout rather than by the carrier. Raising a budget here means raising
//! the host serve timeout and the client wait with it, and none of them may
//! reach the carrier's 60 s.
//!
//! The serving layer adds its own deadline to each serve on top of these —
//! 30 s for tip, headers and filter headers, 40 s for filters, 50 s for a
//! block — a little under the host serve timeouts above, so a serve nobody is
//! waiting for any more is dropped, its requests with it (see
//! [`crate::chain::raw_serve`]).
//!
//! # Reply sizes
//!
//! A filter-headers read covers at most [`FILTER_HEADERS_PER_REPLY`] blocks of
//! the span asked, keeping only the headers of each batch it reads; a filters
//! read stops once [`FILTER_BYTES_PER_REPLY`] of filters are held. Either
//! answers a prefix of the span then, as [`FilterSource`] allows.
//!
//! # Credentials
//!
//! Never logged, never in a `Debug` rendering, never in an error, never in
//! [`RawSourceStatus`]. A URL carrying `user:password@` has them moved into
//! the basic-auth header and removed from the URL that errors might print.
//! Over plain `http://` credentials are only sent to a loopback host;
//! anywhere else the URL must be `https://`.

use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use bitcoin::block::Header;
use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::FromHex;
use bitcoin::{Block, BlockHash};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::chain::cbf::source::{
	BlockFilter, BlockId, FilterHeader, FilterHeaders, FilterSource, IndexedFilter, SourceError,
};
use crate::chain::provider::{
	MAX_FILTERS_PER_REQUEST, MAX_FILTER_HEADERS_PER_REQUEST, MAX_HEADERS_PER_REQUEST,
};
use crate::chain::raw_serve::{FILTER_BYTES_PER_REPLY, FILTER_HEADERS_PER_REPLY};

/// Connecting (TCP + TLS) to the RPC endpoint.
pub(crate) const RAW_RPC_CONNECT_TIMEOUT_SECS: u64 = 10;
/// One small call, or a batch of up to [`MAX_HEADERS_PER_REQUEST`]
/// `getblockhash` / `getblockheader` calls (~200 KiB either way).
pub(crate) const RAW_RPC_CALL_TIMEOUT_SECS: u64 = 20;
/// One batch of [`FILTER_RPC_BATCH`] `getblockfilter` calls: a few MiB of hex
/// on mainnet.
pub(crate) const RAW_RPC_FILTER_BATCH_TIMEOUT_SECS: u64 = 30;
/// One `getblock`: up to 4 MB of block, 8 MB of hex. A block from a local or
/// well-connected node takes 1-2 s; 40 s is generous and, with the connect
/// budget, keeps the host's 54 s `chain.block` serve timeout (and the
/// carrier's 60 s peer-call cap above it) out of reach — see the module docs.
pub(crate) const RAW_RPC_BLOCK_TIMEOUT_SECS: u64 = 40;

/// `getblockfilter` calls per HTTP request. `getblockfilter` returns the whole
/// filter with the header, so this bounds what one reply holds in memory.
pub(crate) const FILTER_RPC_BATCH: usize = 50;

/// Bitcoin Core `RPCErrorCode`s this source tells apart.
const RPC_INVALID_ADDRESS_OR_KEY: i64 = -5;
const RPC_INVALID_PARAMETER: i64 = -8;
const RPC_IN_WARMUP: i64 = -28;
const RPC_METHOD_NOT_FOUND: i64 = -32601;

/// What `getblockfilter` says when the node runs without `-blockfilterindex`.
const NO_FILTER_INDEX_MARKER: &str = "Index is not enabled for filtertype";

/// The reason carried by every filter call against a bitcoind without the
/// index — stable, so logs and status can say plainly what is missing.
pub(crate) const NO_FILTER_INDEX_REASON: &str = "rpc source has no blockfilterindex";

/// How a Pro node's raw chain source is doing, for the operator; see
/// [`Node::raw_chain_source_status`].
///
/// Never carries a credential: errors name the endpoint by
/// `scheme://host:port` only.
///
/// [`Node::raw_chain_source_status`]: crate::Node::raw_chain_source_status
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RawSourceStatus {
	/// `true` when a raw source serves; `false` when one was set but its
	/// configuration was refused at build time — `last_error` says why, and
	/// raw serving is off.
	pub configured: bool,
	/// When the source last answered (UNIX seconds) — data, or a clean "not
	/// there".
	pub last_ok_unix: Option<u64>,
	/// The source's last failure: unreachable, refused, or malformed data.
	pub last_error: Option<String>,
	/// When `last_error` happened (UNIX seconds).
	pub last_error_unix: Option<u64>,
	/// Whether the bitcoind has `-blockfilterindex`: `None` until a filter
	/// read answered or said the index is missing.
	pub has_filter_index: Option<bool>,
}

/// The live [`RawSourceStatus`] a [`BitcoindRpcSource`] keeps up to date.
#[derive(Debug)]
pub(crate) struct RawSourceHealth {
	status: Mutex<RawSourceStatus>,
}

fn unix_now() -> Option<u64> {
	SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}

impl RawSourceHealth {
	/// A configured source that has not been asked anything yet.
	pub(crate) fn new() -> Self {
		Self { status: Mutex::new(RawSourceStatus { configured: true, ..Default::default() }) }
	}

	/// A source whose configuration was refused, for `reason`.
	pub(crate) fn refused(reason: String) -> Self {
		Self {
			status: Mutex::new(RawSourceStatus {
				configured: false,
				last_error: Some(reason),
				last_error_unix: unix_now(),
				..Default::default()
			}),
		}
	}

	/// Notes how a call went. `filter_read` marks a `getblockfilter` read,
	/// which is what tells whether the index is there.
	pub(crate) fn record<T>(&self, result: &Result<T, SourceError>, filter_read: bool) {
		let mut status = self.status.lock().unwrap_or_else(|e| e.into_inner());
		match result {
			Ok(_) => {
				status.last_ok_unix = unix_now();
				if filter_read {
					status.has_filter_index = Some(true);
				}
			},
			Err(SourceError::NotFound(_)) => status.last_ok_unix = unix_now(),
			Err(e) => {
				if let SourceError::Unavailable { reason, .. } = e {
					if reason.starts_with(NO_FILTER_INDEX_REASON) {
						status.has_filter_index = Some(false);
					}
				}
				status.last_error = Some(e.to_string());
				status.last_error_unix = unix_now();
			},
		}
	}

	pub(crate) fn snapshot(&self) -> RawSourceStatus {
		self.status.lock().unwrap_or_else(|e| e.into_inner()).clone()
	}
}

/// Whether `host` (as a URL renders it) is this machine: `127.0.0.0/8`,
/// `::1` or `localhost`.
fn is_loopback_host(host: &str) -> bool {
	let bare = host.trim_start_matches('[').trim_end_matches(']');
	match bare.parse::<IpAddr>() {
		Ok(ip) => ip.is_loopback(),
		Err(_) => bare.eq_ignore_ascii_case("localhost"),
	}
}

/// Fold a JSON-RPC error into a [`SourceError`].
///
/// "Not there" (`-5` unknown block, `-8` height out of range) is
/// [`SourceError::NotFound`]; everything else — a missing index, a method the
/// node does not offer or permit, a node still warming up, a pruned block —
/// is [`SourceError::Unavailable`]: nothing was learned about the chain.
pub(crate) fn classify_rpc_error(method: &str, code: i64, message: &str) -> SourceError {
	if message.contains(NO_FILTER_INDEX_MARKER)
		|| (method == "getblockfilter" && code == RPC_METHOD_NOT_FOUND)
	{
		return SourceError::unavailable(format!("{} ({})", NO_FILTER_INDEX_REASON, message));
	}
	match code {
		RPC_INVALID_ADDRESS_OR_KEY | RPC_INVALID_PARAMETER => {
			SourceError::NotFound(format!("{}: {}", method, message))
		},
		RPC_METHOD_NOT_FOUND => {
			SourceError::unavailable(format!("rpc source does not offer {}", method))
		},
		RPC_IN_WARMUP => SourceError::unavailable(format!("rpc source warming up: {}", message)),
		_ => SourceError::unavailable(format!("{} failed ({}): {}", method, code, message)),
	}
}

/// Parse a certificate pin: 64 hex digits, optionally `:`-separated, any case.
pub(crate) fn parse_cert_pin(pin: &str) -> Result<[u8; 32], String> {
	let cleaned: String = pin.trim().chars().filter(|c| *c != ':').collect();
	let bytes =
		Vec::<u8>::from_hex(&cleaned).map_err(|_| "certificate pin is not hex".to_string())?;
	bytes.try_into().map_err(|_| "certificate pin is not a SHA-256 (64 hex digits)".to_string())
}

/// Does `der` hash to `pin`?
pub(crate) fn cert_matches_pin(pin: &[u8; 32], der: &[u8]) -> bool {
	sha256::Hash::hash(der).to_byte_array() == *pin
}

/// A rustls verifier that trusts exactly one leaf certificate, by hash.
#[derive(Debug)]
pub(crate) struct PinnedCertVerifier {
	pin: [u8; 32],
	provider: Arc<rustls::crypto::CryptoProvider>,
}

impl PinnedCertVerifier {
	pub(crate) fn new(pin: [u8; 32]) -> Self {
		Self { pin, provider: Arc::new(rustls::crypto::ring::default_provider()) }
	}
}

impl rustls::client::danger::ServerCertVerifier for PinnedCertVerifier {
	fn verify_server_cert(
		&self, end_entity: &rustls::pki_types::CertificateDer<'_>,
		_intermediates: &[rustls::pki_types::CertificateDer<'_>],
		_server_name: &rustls::pki_types::ServerName<'_>, _ocsp_response: &[u8],
		_now: rustls::pki_types::UnixTime,
	) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
		if cert_matches_pin(&self.pin, end_entity.as_ref()) {
			Ok(rustls::client::danger::ServerCertVerified::assertion())
		} else {
			Err(rustls::Error::General(
				"server certificate does not match the pinned SHA-256".to_string(),
			))
		}
	}

	fn verify_tls12_signature(
		&self, message: &[u8], cert: &rustls::pki_types::CertificateDer<'_>,
		dss: &rustls::DigitallySignedStruct,
	) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		rustls::crypto::verify_tls12_signature(
			message,
			cert,
			dss,
			&self.provider.signature_verification_algorithms,
		)
	}

	fn verify_tls13_signature(
		&self, message: &[u8], cert: &rustls::pki_types::CertificateDer<'_>,
		dss: &rustls::DigitallySignedStruct,
	) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		rustls::crypto::verify_tls13_signature(
			message,
			cert,
			dss,
			&self.provider.signature_verification_algorithms,
		)
	}

	fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
		self.provider.signature_verification_algorithms.supported_schemes()
	}
}

#[derive(Deserialize)]
struct RpcErrorObject {
	code: i64,
	message: String,
}

#[derive(Deserialize)]
struct RpcReply {
	#[serde(default)]
	result: Value,
	#[serde(default)]
	error: Option<RpcErrorObject>,
	#[serde(default)]
	id: Value,
}

/// Raw BIP157/158 data from a bitcoind's JSON-RPC interface.
pub(crate) struct BitcoindRpcSource {
	client: reqwest::Client,
	url: reqwest::Url,
	auth: Option<(String, String)>,
	/// `scheme://host:port`, for logs.
	endpoint: String,
	next_id: AtomicU64,
	health: Arc<RawSourceHealth>,
}

impl fmt::Debug for BitcoindRpcSource {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("BitcoindRpcSource")
			.field("endpoint", &self.endpoint)
			.field("auth", &self.auth.as_ref().map(|_| "<redacted>"))
			.finish_non_exhaustive()
	}
}

impl BitcoindRpcSource {
	/// A source reading `url` (`http://` or `https://`).
	///
	/// `user`/`password` are sent as basic auth when `user` is non-empty;
	/// otherwise any `user:password@` in the URL is used. Credentials over
	/// `http://` are refused unless the host is loopback (`127.0.0.0/8`,
	/// `::1`, `localhost`): they would cross the network in the clear.
	/// `cert_sha256` pins the server's leaf certificate and requires
	/// `https://`. The error is a reason fit for a log: it never carries a
	/// credential.
	pub(crate) fn new(
		url: &str, user: Option<String>, password: Option<String>, cert_sha256: Option<&str>,
	) -> Result<Self, String> {
		let mut url = reqwest::Url::parse(url).map_err(|e| format!("invalid rpc url: {}", e))?;
		let https = match url.scheme() {
			"https" => true,
			"http" => false,
			other => return Err(format!("unsupported rpc url scheme {}", other)),
		};
		let host = url.host_str().ok_or_else(|| "rpc url has no host".to_string())?.to_string();

		let url_auth = if url.username().is_empty() {
			None
		} else {
			Some((url.username().to_string(), url.password().unwrap_or_default().to_string()))
		};
		let _ = url.set_username("");
		let _ = url.set_password(None);
		let auth = match user.filter(|u| !u.is_empty()) {
			Some(user) => Some((user, password.unwrap_or_default())),
			None => url_auth,
		};

		if !https && auth.is_some() && !is_loopback_host(&host) {
			return Err(format!(
				"refusing to send rpc credentials over plain http:// to {}: use https://, \
				 or a loopback host (127.0.0.0/8, ::1, localhost)",
				host
			));
		}

		let endpoint = match url.port_or_known_default() {
			Some(port) => format!("{}://{}:{}", url.scheme(), host, port),
			None => format!("{}://{}", url.scheme(), host),
		};

		let mut builder = reqwest::Client::builder()
			.connect_timeout(Duration::from_secs(RAW_RPC_CONNECT_TIMEOUT_SECS));
		if let Some(pin) = cert_sha256.map(str::trim).filter(|p| !p.is_empty()) {
			if !https {
				return Err("a certificate pin needs an https:// rpc url".to_string());
			}
			let pin = parse_cert_pin(pin)?;
			let provider = Arc::new(rustls::crypto::ring::default_provider());
			let tls = rustls::ClientConfig::builder_with_provider(provider)
				.with_safe_default_protocol_versions()
				.map_err(|e| format!("tls setup failed: {}", e))?
				.dangerous()
				.with_custom_certificate_verifier(Arc::new(PinnedCertVerifier::new(pin)))
				.with_no_client_auth();
			builder = builder.use_preconfigured_tls(tls);
		}
		let client = builder.build().map_err(|e| format!("http client setup failed: {}", e))?;

		Ok(Self {
			client,
			url,
			auth,
			endpoint,
			next_id: AtomicU64::new(1),
			health: Arc::new(RawSourceHealth::new()),
		})
	}

	/// `scheme://host:port` of the RPC endpoint, credential-free.
	pub(crate) fn endpoint(&self) -> &str {
		&self.endpoint
	}

	/// The status this source keeps up to date as it is asked.
	pub(crate) fn health(&self) -> Arc<RawSourceHealth> {
		Arc::clone(&self.health)
	}

	fn transport_error(&self, e: reqwest::Error) -> SourceError {
		let e = e.without_url();
		SourceError::Unavailable {
			reason: format!("rpc source {} unreachable: {}", self.endpoint, e),
			timed_out: e.is_timeout(),
		}
	}

	/// POST one JSON-RPC body and parse the reply as JSON.
	///
	/// Bitcoin Core answers a failed legacy (1.0) call with HTTP 404 or 500
	/// *and* a JSON error body, so a non-2xx status with a JSON body is handed
	/// back for the caller to classify; only a status without one is an
	/// error here.
	async fn post(&self, body: &Value, timeout: Duration) -> Result<Value, SourceError> {
		let mut req = self.client.post(self.url.clone()).timeout(timeout).json(body);
		if let Some((user, password)) = &self.auth {
			req = req.basic_auth(user, Some(password));
		}
		let resp = req.send().await.map_err(|e| self.transport_error(e))?;
		let status = resp.status();
		if status == reqwest::StatusCode::UNAUTHORIZED {
			return Err(SourceError::unavailable(format!(
				"rpc source {} rejected the credentials",
				self.endpoint
			)));
		}
		if status == reqwest::StatusCode::FORBIDDEN {
			return Err(SourceError::unavailable(format!(
				"rpc source {} does not permit this method",
				self.endpoint
			)));
		}
		let bytes = resp.bytes().await.map_err(|e| self.transport_error(e))?;
		match serde_json::from_slice::<Value>(&bytes) {
			Ok(value) => Ok(value),
			Err(_) if status.is_success() => {
				Err(SourceError::Invalid(format!("rpc source {} sent non-JSON", self.endpoint)))
			},
			Err(_) => Err(SourceError::unavailable(format!(
				"rpc source {} answered HTTP {}",
				self.endpoint, status
			))),
		}
	}

	fn request(&self, method: &str, params: Value) -> (u64, Value) {
		let id = self.next_id.fetch_add(1, Ordering::Relaxed);
		(id, json!({ "jsonrpc": "1.0", "id": id, "method": method, "params": params }))
	}

	fn reply_result(method: &str, reply: RpcReply) -> Result<Value, SourceError> {
		if let Some(err) = reply.error {
			return Err(classify_rpc_error(method, err.code, &err.message));
		}
		if reply.result.is_null() {
			return Err(SourceError::Invalid(format!("{} returned no result", method)));
		}
		Ok(reply.result)
	}

	/// One call.
	async fn call(
		&self, method: &str, params: Value, timeout: Duration,
	) -> Result<Value, SourceError> {
		let (_, body) = self.request(method, params);
		let value = self.post(&body, timeout).await?;
		let reply: RpcReply = serde_json::from_value(value)
			.map_err(|e| SourceError::Invalid(format!("{} reply: {}", method, e)))?;
		Self::reply_result(method, reply)
	}

	/// Many calls of one method in one HTTP request, results in `params`
	/// order. The outer error is the request's; each inner one is its call's.
	async fn batch(
		&self, method: &str, params: Vec<Value>, timeout: Duration,
	) -> Result<Vec<Result<Value, SourceError>>, SourceError> {
		if params.is_empty() {
			return Ok(Vec::new());
		}
		let (ids, bodies): (Vec<u64>, Vec<Value>) =
			params.into_iter().map(|p| self.request(method, p)).unzip();
		let value = self.post(&Value::Array(bodies), timeout).await?;
		let replies = match value {
			Value::Array(replies) => replies,
			// A server that rejects the batch as a whole answers one object.
			other => {
				let reply: RpcReply = serde_json::from_value(other)
					.map_err(|e| SourceError::Invalid(format!("{} batch reply: {}", method, e)))?;
				return Err(match reply.error {
					Some(err) => classify_rpc_error(method, err.code, &err.message),
					None => SourceError::Invalid(format!("{} batch reply is not a list", method)),
				});
			},
		};
		let mut by_id = std::collections::HashMap::with_capacity(replies.len());
		for reply in replies {
			let reply: RpcReply = serde_json::from_value(reply)
				.map_err(|e| SourceError::Invalid(format!("{} batch reply: {}", method, e)))?;
			if let Some(id) = reply.id.as_u64() {
				by_id.insert(id, reply);
			}
		}
		ids.into_iter()
			.map(|id| {
				let reply = by_id.remove(&id).ok_or_else(|| {
					SourceError::Invalid(format!("{} batch reply is missing a call", method))
				})?;
				Ok(Self::reply_result(method, reply))
			})
			.collect()
	}

	/// Best-chain hashes from `from_height`, at most `count`, stopping early
	/// at the tip. [`SourceError::NotFound`] when `from_height` is above it.
	async fn best_chain_hashes(
		&self, from_height: u32, count: u32,
	) -> Result<Vec<BlockHash>, SourceError> {
		let params = (0..count).map(|i| json!([from_height as u64 + i as u64])).collect();
		let results = self
			.batch("getblockhash", params, Duration::from_secs(RAW_RPC_CALL_TIMEOUT_SECS))
			.await?;
		let mut hashes = Vec::with_capacity(results.len());
		for result in results {
			match result {
				Ok(value) => hashes.push(parse_block_hash(&value, "getblockhash")?),
				// Past the tip: the span ends here.
				Err(SourceError::NotFound(_)) if !hashes.is_empty() => break,
				Err(e) => return Err(e),
			}
		}
		Ok(hashes)
	}

	/// The best-chain hashes of `first_height..=height(stop_hash)`, refusing a
	/// span wider than `max_span` before fetching it.
	async fn resolve_span(
		&self, first_height: u32, stop_hash: BlockHash, max_span: u32,
	) -> Result<Vec<BlockHash>, SourceError> {
		let header = self
			.call(
				"getblockheader",
				json!([stop_hash.to_string(), true]),
				Duration::from_secs(RAW_RPC_CALL_TIMEOUT_SECS),
			)
			.await?;
		// `confirmations` is -1 for a block off the best chain.
		if header.get("confirmations").and_then(Value::as_i64).unwrap_or(-1) < 0 {
			return Err(SourceError::NotFound(format!(
				"stop hash {} is not on the best chain",
				stop_hash
			)));
		}
		let stop_height = parse_height(&header)?;
		if stop_height < first_height {
			return Err(SourceError::Invalid(format!(
				"stop height {} is below start height {}",
				stop_height, first_height
			)));
		}
		let span = stop_height - first_height + 1;
		if span > max_span {
			return Err(SourceError::Invalid(format!(
				"span of {} blocks exceeds the {} one request may cover",
				span, max_span
			)));
		}
		let hashes = self.best_chain_hashes(first_height, span).await?;
		if hashes.len() as u32 != span || hashes.last() != Some(&stop_hash) {
			return Err(SourceError::NotFound(format!(
				"stop hash {} left the best chain while reading",
				stop_hash
			)));
		}
		Ok(hashes)
	}

	/// `getblockfilter` for each hash, in batches of [`FILTER_RPC_BATCH`],
	/// handing each (filter, header) to `each` in order and dropping it
	/// there: only what `each` keeps is held. Stops after the batch in which
	/// `each` first answers `false`.
	async fn for_each_block_filter(
		&self, hashes: &[BlockHash],
		mut each: impl FnMut(BlockFilter, FilterHeader) -> Result<bool, SourceError>,
	) -> Result<(), SourceError> {
		for batch in hashes.chunks(FILTER_RPC_BATCH) {
			let params = batch.iter().map(|h| json!([h.to_string(), "basic"])).collect();
			let results = self
				.batch(
					"getblockfilter",
					params,
					Duration::from_secs(RAW_RPC_FILTER_BATCH_TIMEOUT_SECS),
				)
				.await?;
			for result in results {
				let value = result?;
				let filter_hex = value
					.get("filter")
					.and_then(Value::as_str)
					.ok_or_else(|| SourceError::Invalid("getblockfilter: no filter".into()))?;
				let header = value
					.get("header")
					.and_then(Value::as_str)
					.ok_or_else(|| SourceError::Invalid("getblockfilter: no header".into()))?
					.parse::<FilterHeader>()
					.map_err(|e| SourceError::Invalid(format!("getblockfilter header: {}", e)))?;
				let content = Vec::<u8>::from_hex(filter_hex)
					.map_err(|e| SourceError::Invalid(format!("getblockfilter filter: {}", e)))?;
				if !each(BlockFilter { content }, header)? {
					return Ok(());
				}
			}
		}
		Ok(())
	}

	async fn read_tip(&self) -> Result<BlockId, SourceError> {
		let timeout = Duration::from_secs(RAW_RPC_CALL_TIMEOUT_SECS);
		let hash = parse_block_hash(
			&self.call("getbestblockhash", json!([]), timeout).await?,
			"getbestblockhash",
		)?;
		let header = self.call("getblockheader", json!([hash.to_string(), true]), timeout).await?;
		Ok(BlockId { height: parse_height(&header)?, hash })
	}

	async fn read_headers(&self, from_height: u32, count: u32) -> Result<Vec<Header>, SourceError> {
		let count = count.min(MAX_HEADERS_PER_REQUEST);
		if count == 0 {
			return Ok(Vec::new());
		}
		let hashes = self.best_chain_hashes(from_height, count).await?;
		let params = hashes.iter().map(|h| json!([h.to_string(), false])).collect();
		let results = self
			.batch("getblockheader", params, Duration::from_secs(RAW_RPC_CALL_TIMEOUT_SECS))
			.await?;
		let mut headers: Vec<Header> = Vec::with_capacity(hashes.len());
		for (hash, result) in hashes.iter().zip(results) {
			let header: Header = parse_hex(&result?, "getblockheader")?;
			if header.block_hash() != *hash {
				return Err(SourceError::Invalid(format!(
					"getblockheader for {} returned another header",
					hash
				)));
			}
			if let Some(prev) = headers.last() {
				if header.prev_blockhash != prev.block_hash() {
					// The two batches straddled a reorg.
					return Err(SourceError::unavailable(
						"best chain changed while reading headers",
					));
				}
			}
			headers.push(header);
		}
		Ok(headers)
	}

	/// The span's filter headers, or those of its first
	/// [`FILTER_HEADERS_PER_REPLY`] blocks: each batch of filters read is
	/// checked against its headers and dropped, only the headers kept.
	async fn read_filter_headers(
		&self, start_height: u32, stop_hash: BlockHash,
	) -> Result<FilterHeaders, SourceError> {
		// Read one block below the span too, for `previous`.
		let (first_height, max_span) = match start_height {
			0 => (0, MAX_FILTER_HEADERS_PER_REQUEST),
			h => (h - 1, MAX_FILTER_HEADERS_PER_REQUEST + 1),
		};
		let hashes = self.resolve_span(first_height, stop_hash, max_span).await?;
		if start_height > 0 && hashes.len() < 2 {
			return Err(SourceError::Invalid(format!(
				"stop hash {} is below start height {}",
				stop_hash, start_height
			)));
		}
		let below = usize::from(start_height > 0);
		let read = hashes.len().min(FILTER_HEADERS_PER_REPLY as usize + below);

		let mut previous = FilterHeader::all_zeros();
		let mut headers: Vec<FilterHeader> = Vec::with_capacity(read - below);
		let mut height = first_height;
		self.for_each_block_filter(&hashes[..read], |filter, header| {
			if height < start_height {
				previous = header;
			} else {
				let expected_prev = headers.last().copied().unwrap_or(previous);
				if filter.filter_header(&expected_prev) != header {
					return Err(SourceError::Invalid(format!(
						"filter header at height {} does not commit to its filter",
						height
					)));
				}
				headers.push(header);
			}
			height += 1;
			Ok(true)
		})
		.await?;
		Ok(FilterHeaders { previous, headers })
	}

	/// The span's filters, or as many from its start as fit in
	/// [`FILTER_BYTES_PER_REPLY`] — at least one.
	async fn read_filters(
		&self, start_height: u32, stop_hash: BlockHash,
	) -> Result<Vec<IndexedFilter>, SourceError> {
		let hashes = self.resolve_span(start_height, stop_hash, MAX_FILTERS_PER_REQUEST).await?;
		let mut out: Vec<IndexedFilter> = Vec::with_capacity(hashes.len());
		let mut bytes = 0usize;
		self.for_each_block_filter(&hashes, |filter, _header| {
			bytes = bytes.saturating_add(filter.content.len());
			if !out.is_empty() && bytes > FILTER_BYTES_PER_REPLY {
				return Ok(false);
			}
			let i = out.len();
			out.push(IndexedFilter {
				height: start_height + i as u32,
				block_hash: hashes[i],
				filter,
			});
			Ok(true)
		})
		.await?;
		Ok(out)
	}

	async fn read_block(&self, hash: BlockHash) -> Result<Block, SourceError> {
		let value = self
			.call(
				"getblock",
				json!([hash.to_string(), 0]),
				Duration::from_secs(RAW_RPC_BLOCK_TIMEOUT_SECS),
			)
			.await?;
		let block: Block = parse_hex(&value, "getblock")?;
		if block.block_hash() != hash {
			return Err(SourceError::Invalid(format!(
				"getblock for {} returned another block",
				hash
			)));
		}
		Ok(block)
	}
}

fn parse_block_hash(value: &Value, what: &str) -> Result<BlockHash, SourceError> {
	value
		.as_str()
		.ok_or_else(|| SourceError::Invalid(format!("{}: not a string", what)))?
		.parse::<BlockHash>()
		.map_err(|e| SourceError::Invalid(format!("{}: {}", what, e)))
}

fn parse_height(header: &Value) -> Result<u32, SourceError> {
	header
		.get("height")
		.and_then(Value::as_u64)
		.and_then(|h| u32::try_from(h).ok())
		.ok_or_else(|| SourceError::Invalid("getblockheader: no height".into()))
}

fn parse_hex<T: bitcoin::consensus::Decodable>(
	value: &Value, what: &str,
) -> Result<T, SourceError> {
	let hex = value.as_str().ok_or_else(|| SourceError::Invalid(format!("{}: not hex", what)))?;
	let bytes =
		Vec::<u8>::from_hex(hex).map_err(|e| SourceError::Invalid(format!("{}: {}", what, e)))?;
	deserialize(&bytes).map_err(|e| SourceError::Invalid(format!("{}: {}", what, e)))
}

/// Every read is noted in the source's [`RawSourceHealth`].
#[async_trait]
impl FilterSource for BitcoindRpcSource {
	fn name(&self) -> &'static str {
		"bitcoind_rpc"
	}

	async fn tip(&self) -> Result<BlockId, SourceError> {
		let result = self.read_tip().await;
		self.health.record(&result, false);
		result
	}

	/// Clamped to [`MAX_HEADERS_PER_REQUEST`]; the contract allows fewer.
	async fn headers(&self, from_height: u32, count: u32) -> Result<Vec<Header>, SourceError> {
		let result = self.read_headers(from_height, count).await;
		self.health.record(&result, false);
		result
	}

	async fn filter_headers(
		&self, start_height: u32, stop_hash: BlockHash,
	) -> Result<FilterHeaders, SourceError> {
		let result = self.read_filter_headers(start_height, stop_hash).await;
		self.health.record(&result, true);
		result
	}

	async fn filters(
		&self, start_height: u32, stop_hash: BlockHash,
	) -> Result<Vec<IndexedFilter>, SourceError> {
		let result = self.read_filters(start_height, stop_hash).await;
		self.health.record(&result, true);
		result
	}

	async fn block(&self, hash: BlockHash) -> Result<Block, SourceError> {
		let result = self.read_block(hash).await;
		self.health.record(&result, false);
		result
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use std::io::{Read, Write};
	use std::net::TcpListener;
	use std::sync::Mutex;

	use bitcoin::consensus::encode::serialize;
	use bitcoin::hex::DisplayHex;

	use rustls::client::danger::ServerCertVerifier;

	use crate::chain::wire_convert::synthetic_block;

	#[test]
	fn rpc_errors_are_classified() {
		let no_index =
			classify_rpc_error("getblockfilter", -1, "Index is not enabled for filtertype basic");
		match no_index {
			SourceError::Unavailable { reason, timed_out: false } => {
				assert!(reason.starts_with(NO_FILTER_INDEX_REASON), "{}", reason)
			},
			other => panic!("{:?}", other),
		}
		assert!(matches!(
			classify_rpc_error("getblockfilter", -32601, "Method not found"),
			SourceError::Unavailable { reason, .. } if reason.starts_with(NO_FILTER_INDEX_REASON)
		));
		assert!(matches!(
			classify_rpc_error("getblock", -32601, "Method not found"),
			SourceError::Unavailable { reason, .. } if reason.contains("does not offer getblock")
		));
		assert!(matches!(
			classify_rpc_error("getblockheader", -5, "Block not found"),
			SourceError::NotFound(_)
		));
		assert!(matches!(
			classify_rpc_error("getblockhash", -8, "Block height out of range"),
			SourceError::NotFound(_)
		));
		assert!(matches!(
			classify_rpc_error("getblock", -1, "Block not available (pruned data)"),
			SourceError::Unavailable { .. }
		));
		assert!(matches!(
			classify_rpc_error("getbestblockhash", -28, "Loading block index..."),
			SourceError::Unavailable { .. }
		));
	}

	#[test]
	fn cert_pins_parse_and_match() {
		let der = b"not really a certificate, but the pin only hashes it".to_vec();
		let pin_hex = sha256::Hash::hash(&der).to_byte_array().to_lower_hex_string();
		let pin = parse_cert_pin(&pin_hex).unwrap();
		assert_eq!(parse_cert_pin(&pin_hex.to_uppercase()).unwrap(), pin);
		let colons: String = pin_hex
			.as_bytes()
			.chunks(2)
			.map(|c| std::str::from_utf8(c).unwrap())
			.collect::<Vec<_>>()
			.join(":");
		assert_eq!(parse_cert_pin(&colons).unwrap(), pin);
		assert!(parse_cert_pin("abcd").is_err());
		assert!(parse_cert_pin(&"zz".repeat(32)).is_err());

		assert!(cert_matches_pin(&pin, &der));
		assert!(!cert_matches_pin(&pin, b"another certificate"));
	}

	#[test]
	fn the_pinned_verifier_accepts_only_the_pinned_certificate() {
		let der = b"the pinned certificate".to_vec();
		let pin = sha256::Hash::hash(&der).to_byte_array();
		let verifier = PinnedCertVerifier::new(pin);
		let name = rustls::pki_types::ServerName::try_from("lsp.example").unwrap();
		let now = rustls::pki_types::UnixTime::now();

		let pinned = rustls::pki_types::CertificateDer::from(der);
		assert!(verifier.verify_server_cert(&pinned, &[], &name, &[], now).is_ok());

		let other = rustls::pki_types::CertificateDer::from(b"someone else".to_vec());
		assert!(verifier.verify_server_cert(&other, &[], &name, &[], now).is_err());
		assert!(!verifier.supported_verify_schemes().is_empty());
	}

	#[test]
	fn setup_checks_the_url_and_pin_and_hides_credentials() {
		let pin = "ab".repeat(32);
		assert!(BitcoindRpcSource::new("ftp://host", None, None, None).is_err());
		assert!(BitcoindRpcSource::new("not a url", None, None, None).is_err());
		assert!(
			BitcoindRpcSource::new("http://host:8332", None, None, Some(&pin)).is_err(),
			"a pin needs TLS"
		);
		assert!(BitcoindRpcSource::new("https://host:8443", None, None, Some("abc")).is_err());
		assert!(BitcoindRpcSource::new("https://host:8443", None, None, Some(&pin)).is_ok());

		let source = BitcoindRpcSource::new(
			"https://urluser:urlsecret@host:8443/",
			Some("user".into()),
			Some("s3cret-password".into()),
			None,
		)
		.unwrap();
		assert_eq!(source.endpoint(), "https://host:8443");
		let debug = format!("{:?}", source);
		assert!(!debug.contains("s3cret-password") && !debug.contains("urlsecret"), "{}", debug);
		assert!(!source.url.as_str().contains("urlsecret"));
		assert_eq!(source.auth.as_ref().unwrap().0, "user", "explicit credentials win");

		let source =
			BitcoindRpcSource::new("http://urluser:urlsecret@127.0.0.1", None, None, None).unwrap();
		assert_eq!(source.auth, Some(("urluser".into(), "urlsecret".into())));
		assert!(!source.url.as_str().contains("urlsecret"));
	}

	#[test]
	fn credentials_go_over_plain_http_only_to_a_loopback_host() {
		let with_creds = |url: &str| {
			BitcoindRpcSource::new(url, Some("user".into()), Some("s3cret".into()), None)
		};
		for remote in ["http://10.0.0.5:8332", "http://node.example:8332", "http://[2001:db8::1]"] {
			let err = with_creds(remote).expect_err(remote);
			assert!(err.contains("plain http://") && err.contains("https://"), "{}", err);
			assert!(!err.contains("s3cret"), "{}", err);
		}
		let err = BitcoindRpcSource::new("http://u:urlsecret@10.0.0.5", None, None, None)
			.expect_err("credentials in the URL count too");
		assert!(!err.contains("urlsecret"), "{}", err);

		for local in [
			"http://127.0.0.1:8332",
			"http://127.3.2.1:8332",
			"http://[::1]:8332",
			"http://localhost:8332",
			"http://LocalHost:8332",
			"https://node.example:8443",
		] {
			assert!(with_creds(local).is_ok(), "{}", local);
		}
		// No credentials, nothing to leak: any host.
		assert!(BitcoindRpcSource::new("http://node.example:8332", None, None, None).is_ok());
		assert!(
			BitcoindRpcSource::new("http://node.example:8332", Some(String::new()), None, None)
				.is_ok(),
			"an empty user is no credential"
		);
	}

	// ── a canned bitcoind ────────────────────────────────────────────────

	/// A regtest-shaped chain the mock serves: `blocks[h]` at height `h`.
	struct MockChain {
		blocks: Vec<Block>,
		filters: Vec<BlockFilter>,
		filter_headers: Vec<FilterHeader>,
		filter_index: bool,
	}

	impl MockChain {
		fn new(len: u32, filter_index: bool) -> Self {
			let mut blocks: Vec<Block> = Vec::new();
			for i in 0..len {
				let mut block = synthetic_block(10, i);
				if let Some(prev) = blocks.last() {
					block.header.prev_blockhash = prev.block_hash();
				}
				blocks.push(block);
			}
			let filters: Vec<BlockFilter> =
				(0..len).map(|i| BlockFilter::new(&[1, i as u8, 0xab])).collect();
			let mut prev = FilterHeader::all_zeros();
			let filter_headers = filters
				.iter()
				.map(|f| {
					prev = f.filter_header(&prev);
					prev
				})
				.collect();
			Self { blocks, filters, filter_headers, filter_index }
		}

		/// Every filter `len` bytes long, the filter headers chained over them.
		fn with_filter_bytes(mut self, len: usize) -> Self {
			self.filters = (0..self.blocks.len())
				.map(|i| {
					let mut content = vec![0xab; len];
					content[..4].copy_from_slice(&(i as u32).to_le_bytes());
					BlockFilter::new(&content)
				})
				.collect();
			let mut prev = FilterHeader::all_zeros();
			self.filter_headers = self
				.filters
				.iter()
				.map(|f| {
					prev = f.filter_header(&prev);
					prev
				})
				.collect();
			self
		}

		fn height_of(&self, hash: &str) -> Option<usize> {
			self.blocks.iter().position(|b| b.block_hash().to_string() == hash)
		}

		fn answer(&self, method: &str, params: &Value) -> Result<Value, (i64, String)> {
			let not_found = || (-5, "Block not found".to_string());
			match method {
				"getbestblockhash" => Ok(json!(self.blocks.last().unwrap().block_hash())),
				"getblockhash" => {
					let h = params[0].as_u64().unwrap() as usize;
					self.blocks
						.get(h)
						.map(|b| json!(b.block_hash()))
						.ok_or((-8, "Block height out of range".to_string()))
				},
				"getblockheader" => {
					let h = self.height_of(params[0].as_str().unwrap()).ok_or_else(not_found)?;
					if params[1].as_bool().unwrap() {
						Ok(json!({ "height": h, "confirmations": self.blocks.len() - h }))
					} else {
						Ok(json!(serialize(&self.blocks[h].header).to_lower_hex_string()))
					}
				},
				"getblockfilter" => {
					if !self.filter_index {
						return Err((-1, "Index is not enabled for filtertype basic".into()));
					}
					let h = self.height_of(params[0].as_str().unwrap()).ok_or_else(not_found)?;
					Ok(json!({
						"filter": self.filters[h].content.to_lower_hex_string(),
						"header": self.filter_headers[h].to_string(),
					}))
				},
				"getblock" => {
					let h = self.height_of(params[0].as_str().unwrap()).ok_or_else(not_found)?;
					Ok(json!(serialize(&self.blocks[h]).to_lower_hex_string()))
				},
				_ => Err((-32601, "Method not found".into())),
			}
		}

		fn reply(&self, call: &Value) -> Value {
			let method = call["method"].as_str().unwrap();
			match self.answer(method, &call["params"]) {
				Ok(result) => json!({ "result": result, "error": null, "id": call["id"] }),
				Err((code, message)) => json!({
					"result": null,
					"error": { "code": code, "message": message },
					"id": call["id"],
				}),
			}
		}
	}

	struct MockBitcoind {
		url: String,
		authorizations: Arc<Mutex<Vec<Option<String>>>>,
	}

	/// Serve `chain` over HTTP on a local port, one request per connection.
	/// Batches are answered in reverse order, as JSON-RPC permits; a single
	/// call that fails is answered HTTP 500, as bitcoind does. With
	/// `status_override` every request gets that status and an empty body.
	fn mock_bitcoind(chain: MockChain, status_override: Option<u16>) -> MockBitcoind {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let url = format!("http://{}", listener.local_addr().unwrap());
		let authorizations = Arc::new(Mutex::new(Vec::new()));
		let seen = Arc::clone(&authorizations);
		std::thread::spawn(move || {
			for stream in listener.incoming() {
				let Ok(mut stream) = stream else { continue };
				let mut buf = Vec::new();
				let mut chunk = [0u8; 8192];
				let (head_len, content_length) = loop {
					let n = stream.read(&mut chunk).unwrap_or(0);
					if n == 0 {
						break (0, 0);
					}
					buf.extend_from_slice(&chunk[..n]);
					if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
						let head = String::from_utf8_lossy(&buf[..pos]).to_lowercase();
						let len = head
							.lines()
							.find_map(|l| l.strip_prefix("content-length:"))
							.map(|v| v.trim().parse::<usize>().unwrap())
							.unwrap_or(0);
						let auth = head
							.lines()
							.find_map(|l| l.strip_prefix("authorization:"))
							.map(|v| v.trim().to_string());
						seen.lock().unwrap().push(auth);
						break (pos + 4, len);
					}
				};
				if head_len == 0 {
					continue;
				}
				while buf.len() < head_len + content_length {
					let n = stream.read(&mut chunk).unwrap_or(0);
					if n == 0 {
						break;
					}
					buf.extend_from_slice(&chunk[..n]);
				}
				let (status, body) = match status_override {
					Some(status) => (status, String::new()),
					None => {
						let request: Value =
							serde_json::from_slice(&buf[head_len..head_len + content_length])
								.unwrap();
						match request {
							Value::Array(calls) => {
								let mut replies: Vec<Value> =
									calls.iter().map(|c| chain.reply(c)).collect();
								replies.reverse();
								(200, Value::Array(replies).to_string())
							},
							call => {
								let reply = chain.reply(&call);
								let status = if reply["error"].is_null() { 200 } else { 500 };
								(status, reply.to_string())
							},
						}
					},
				};
				let response = format!(
					"HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
					status,
					body.len(),
					body
				);
				let _ = stream.write_all(response.as_bytes());
			}
		});
		MockBitcoind { url, authorizations }
	}

	#[tokio::test]
	async fn reads_headers_filters_and_blocks_from_a_bitcoind() {
		let chain = MockChain::new(12, true);
		let blocks = chain.blocks.clone();
		let filters = chain.filters.clone();
		let filter_headers = chain.filter_headers.clone();
		let mock = mock_bitcoind(chain, None);
		let source =
			BitcoindRpcSource::new(&mock.url, Some("rpcuser".into()), Some("rpcpass".into()), None)
				.unwrap();

		let tip = source.tip().await.unwrap();
		assert_eq!(tip, BlockId { height: 11, hash: blocks[11].block_hash() });

		let headers = source.headers(3, 4).await.unwrap();
		let expected: Vec<Header> = blocks[3..7].iter().map(|b| b.header).collect();
		assert_eq!(headers, expected);
		// Past the tip: fewer, not an error.
		assert_eq!(source.headers(9, 10).await.unwrap().len(), 3);
		assert!(matches!(source.headers(12, 1).await, Err(SourceError::NotFound(_))));

		let fh = source.filter_headers(4, blocks[8].block_hash()).await.unwrap();
		assert_eq!(fh.previous, filter_headers[3]);
		assert_eq!(fh.headers, filter_headers[4..=8].to_vec());
		let from_genesis = source.filter_headers(0, blocks[2].block_hash()).await.unwrap();
		assert_eq!(from_genesis.previous, FilterHeader::all_zeros());
		assert_eq!(from_genesis.headers, filter_headers[0..=2].to_vec());

		let got = source.filters(5, blocks[7].block_hash()).await.unwrap();
		assert_eq!(got.len(), 3);
		for (i, f) in got.iter().enumerate() {
			assert_eq!(f.height, 5 + i as u32);
			assert_eq!(f.block_hash, blocks[5 + i].block_hash());
			assert_eq!(f.filter, filters[5 + i]);
		}

		assert_eq!(source.block(blocks[6].block_hash()).await.unwrap(), blocks[6]);

		// Unknown stop hash and unknown block: not found. Stop below start:
		// a malformed request.
		let stranger = synthetic_block(10, 999).block_hash();
		assert!(matches!(source.filters(0, stranger).await, Err(SourceError::NotFound(_))));
		assert!(matches!(source.block(stranger).await, Err(SourceError::NotFound(_))));
		assert!(matches!(
			source.filters(8, blocks[3].block_hash()).await,
			Err(SourceError::Invalid(_))
		));
		assert!(matches!(
			source.filter_headers(8, blocks[7].block_hash()).await,
			Err(SourceError::Invalid(_))
		));

		// Credentials went as basic auth, on every request.
		let auths = mock.authorizations.lock().unwrap().clone();
		assert!(!auths.is_empty());
		assert!(auths.iter().all(|a| a.as_deref().is_some_and(|a| a.starts_with("basic "))));
	}

	#[tokio::test]
	async fn spans_over_the_limit_are_refused_before_fetching() {
		let mock = mock_bitcoind(MockChain::new(MAX_FILTERS_PER_REQUEST as u32 + 5, true), None);
		let source = BitcoindRpcSource::new(&mock.url, None, None, None).unwrap();
		let tip = source.tip().await.unwrap();
		let before = mock.authorizations.lock().unwrap().len();
		assert!(matches!(source.filters(0, tip.hash).await, Err(SourceError::Invalid(_))));
		assert_eq!(
			mock.authorizations.lock().unwrap().len(),
			before + 1,
			"only the stop hash was resolved"
		);
		assert!(source.filters(5, tip.hash).await.is_ok(), "exactly the limit is fine");
	}

	#[tokio::test]
	async fn filter_reads_answer_a_prefix_when_the_span_is_large() {
		let chain = MockChain::new(260, true).with_filter_bytes(20_000);
		let blocks = chain.blocks.clone();
		let filter_headers = chain.filter_headers.clone();
		let mock = mock_bitcoind(chain, None);
		let source = BitcoindRpcSource::new(&mock.url, None, None, None).unwrap();

		let fh = source.filter_headers(1, blocks[250].block_hash()).await.unwrap();
		assert_eq!(fh.previous, filter_headers[0]);
		assert_eq!(fh.headers, filter_headers[1..=FILTER_HEADERS_PER_REPLY as usize].to_vec());
		let from_genesis = source.filter_headers(0, blocks[259].block_hash()).await.unwrap();
		assert_eq!(from_genesis.headers.len(), FILTER_HEADERS_PER_REPLY as usize);

		let filters = source.filters(100, blocks[199].block_hash()).await.unwrap();
		assert_eq!(filters.len(), FILTER_BYTES_PER_REPLY / 20_000, "as many as fit");
		for (i, f) in filters.iter().enumerate() {
			assert_eq!((f.height, f.block_hash), (100 + i as u32, blocks[100 + i].block_hash()));
		}
	}

	#[tokio::test]
	async fn the_status_follows_the_reads_and_never_shows_credentials() {
		let chain = MockChain::new(4, false);
		let tip_hash = chain.blocks[3].block_hash();
		let mock = mock_bitcoind(chain, None);
		let source =
			BitcoindRpcSource::new(&mock.url, Some("u".into()), Some("s3cret".into()), None)
				.unwrap();
		let health = source.health();
		assert_eq!(
			health.snapshot(),
			RawSourceStatus { configured: true, ..Default::default() },
			"nothing asked yet"
		);

		source.tip().await.unwrap();
		let status = health.snapshot();
		assert!(status.last_ok_unix.is_some() && status.last_error.is_none());
		assert_eq!(status.has_filter_index, None, "not a filter read");

		assert!(source.filters(0, tip_hash).await.is_err());
		let status = health.snapshot();
		assert_eq!(status.has_filter_index, Some(false));
		let error = status.last_error.expect("the failure");
		assert!(error.contains(NO_FILTER_INDEX_REASON), "{}", error);
		assert!(status.last_error_unix.is_some());

		let indexed = mock_bitcoind(MockChain::new(4, true), None);
		let source =
			BitcoindRpcSource::new(&indexed.url, Some("u".into()), Some("s3cret".into()), None)
				.unwrap();
		source.filters(0, tip_hash).await.unwrap();
		assert_eq!(source.health().snapshot().has_filter_index, Some(true));

		// Unreachable: an error that names the endpoint, not the credentials.
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let url = format!("http://{}", listener.local_addr().unwrap());
		drop(listener);
		let source =
			BitcoindRpcSource::new(&url, Some("u".into()), Some("s3cret".into()), None).unwrap();
		assert!(source.tip().await.is_err());
		let status = source.health().snapshot();
		assert!(!format!("{:?}", status).contains("s3cret"), "{:?}", status);
		assert!(status.last_error.is_some());
		assert_eq!(status.last_ok_unix, None);

		let refused = RawSourceHealth::refused("invalid rpc url".into()).snapshot();
		assert!(!refused.configured);
		assert_eq!(refused.last_error.as_deref(), Some("invalid rpc url"));
	}

	#[tokio::test]
	async fn a_bitcoind_without_the_filter_index_says_so() {
		let chain = MockChain::new(4, false);
		let tip_hash = chain.blocks[3].block_hash();
		let mock = mock_bitcoind(chain, None);
		let source = BitcoindRpcSource::new(&mock.url, None, None, None).unwrap();
		for result in [
			source.filters(0, tip_hash).await.map(|_| ()),
			source.filter_headers(1, tip_hash).await.map(|_| ()),
		] {
			match result {
				Err(SourceError::Unavailable { reason, timed_out: false }) => {
					assert!(reason.starts_with(NO_FILTER_INDEX_REASON), "{}", reason)
				},
				other => panic!("{:?}", other),
			}
		}
		// Headers and blocks still work.
		assert_eq!(source.headers(0, 4).await.unwrap().len(), 4);
		assert!(source.block(tip_hash).await.is_ok());
		// No credentials configured, none sent.
		assert!(mock.authorizations.lock().unwrap().iter().all(Option::is_none));
	}

	#[tokio::test]
	async fn http_failures_are_unavailable() {
		for (status, needle) in [(401, "credentials"), (403, "permit"), (502, "HTTP 502")] {
			let mock = mock_bitcoind(MockChain::new(2, true), Some(status));
			let source =
				BitcoindRpcSource::new(&mock.url, Some("u".into()), Some("pw".into()), None)
					.unwrap();
			match source.tip().await {
				Err(SourceError::Unavailable { reason, .. }) => {
					assert!(reason.contains(needle), "{}: {}", status, reason);
					assert!(!reason.contains("pw"), "{}", reason);
				},
				other => panic!("{}: {:?}", status, other),
			}
		}

		// Nothing listening.
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let url = format!("http://{}", listener.local_addr().unwrap());
		drop(listener);
		let source = BitcoindRpcSource::new(&url, None, None, None).unwrap();
		assert!(matches!(
			source.tip().await,
			Err(SourceError::Unavailable { timed_out: false, .. })
		));
	}

	/// Mac probe against a public mainnet RPC (no filter index there):
	///
	/// `cargo test --lib raw_source_publicnode_probe -- --ignored --nocapture`
	#[tokio::test]
	#[ignore]
	async fn raw_source_publicnode_probe() {
		let source =
			BitcoindRpcSource::new("https://bitcoin-rpc.publicnode.com", None, None, None).unwrap();

		let started = std::time::Instant::now();
		let tip = source.tip().await.expect("tip");
		println!("tip: height {} hash {} ({:?})", tip.height, tip.hash, started.elapsed());
		assert!(tip.height > 900_000, "mainnet is past 900k");

		let started = std::time::Instant::now();
		let headers = source.headers(tip.height - 5, 5).await.expect("headers");
		println!("headers: {} from {} ({:?})", headers.len(), tip.height - 5, started.elapsed());
		assert_eq!(headers.len(), 5);
		for pair in headers.windows(2) {
			assert_eq!(pair[1].prev_blockhash, pair[0].block_hash(), "headers connect");
		}
		for header in &headers {
			header.validate_pow(header.target()).expect("proof of work");
		}
		println!("headers: connected, proof of work valid");

		let started = std::time::Instant::now();
		let block = source.block(tip.hash).await.expect("block");
		let size = serialize(&block).len();
		println!(
			"block: {} txs, {} bytes, {} chunks ({:?})",
			block.txdata.len(),
			size,
			crate::chain::wire_convert::block_chunk_count(size),
			started.elapsed()
		);
		assert!(block.check_merkle_root(), "merkle root");
		assert!(block.check_witness_commitment(), "witness commitment");
		println!("block: merkle root and witness commitment valid");

		match source.filters(tip.height, tip.hash).await {
			Err(SourceError::Unavailable { reason, .. }) => {
				println!("filters: unavailable: {}", reason);
				assert!(reason.starts_with(NO_FILTER_INDEX_REASON));
			},
			other => panic!("expected no filter index, got {:?}", other.map(|f| f.len())),
		}
	}
}
