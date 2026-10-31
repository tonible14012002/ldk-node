// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! The background processor's persister, with the network graph and scorer writes made
//! optional.
//!
//! `lightning-background-processor` persists three things through one [`Persister`]: the
//! `ChannelManager`, the network graph and the scorer. A node on a graph it shares with
//! another node (`Builder::set_shared_graph`) must persist its own `ChannelManager` and
//! nothing else: the graph is the primary's to persist, into the primary's store, and a
//! secondary writing the same ~130 MB into its own store on every prune would double the
//! disk for a copy nobody reads back. The blanket `impl Persister for KVStore` cannot say
//! so, hence this wrapper.
//!
//! Every node — primary or secondary — goes through it, so the processor is instantiated
//! for one persister type; the primary's writes are the same three KVStore writes the
//! blanket impl makes.

use std::ops::Deref;
use std::sync::Arc;

use lightning::io;
use lightning::ln::channelmanager::AChannelManager;
use lightning::routing::gossip::NetworkGraph;
use lightning::routing::scoring::WriteableScore;
use lightning::util::logger::Logger as LdkLogger;
use lightning::util::persist::{
	Persister, CHANNEL_MANAGER_PERSISTENCE_KEY,
	CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE, CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
	NETWORK_GRAPH_PERSISTENCE_KEY, NETWORK_GRAPH_PERSISTENCE_PRIMARY_NAMESPACE,
	NETWORK_GRAPH_PERSISTENCE_SECONDARY_NAMESPACE, SCORER_PERSISTENCE_KEY,
	SCORER_PERSISTENCE_PRIMARY_NAMESPACE, SCORER_PERSISTENCE_SECONDARY_NAMESPACE,
};
use lightning::util::ser::Writeable;

use crate::types::DynStore;

/// What of the routing state the persister writes besides the `ChannelManager`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GraphPersistence {
	/// The graph and the scorer are this node's: write them.
	Own,
	/// The graph and the scorer are shared and another node writes them: do not.
	Shared,
}

/// The node's [`Persister`] for the background processor; see the module docs.
pub(crate) struct BackgroundPersister {
	kv_store: Arc<DynStore>,
	graph: GraphPersistence,
}

impl BackgroundPersister {
	pub(crate) fn new(kv_store: Arc<DynStore>, graph: GraphPersistence) -> Self {
		Self { kv_store, graph }
	}

	/// Whether graph and scorer writes reach the store.
	pub(crate) fn persists_graph(&self) -> bool {
		self.graph == GraphPersistence::Own
	}
}

impl<'a, CM: Deref, L: Deref, S: Deref> Persister<'a, CM, L, S> for BackgroundPersister
where
	CM::Target: 'static + AChannelManager,
	L::Target: 'static + LdkLogger,
	S::Target: WriteableScore<'a>,
{
	fn persist_manager(&self, channel_manager: &CM) -> Result<(), io::Error> {
		self.kv_store.write(
			CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
			CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
			CHANNEL_MANAGER_PERSISTENCE_KEY,
			&channel_manager.get_cm().encode(),
		)
	}

	fn persist_graph(&self, network_graph: &NetworkGraph<L>) -> Result<(), io::Error> {
		if !self.persists_graph() {
			return Ok(());
		}
		self.kv_store.write(
			NETWORK_GRAPH_PERSISTENCE_PRIMARY_NAMESPACE,
			NETWORK_GRAPH_PERSISTENCE_SECONDARY_NAMESPACE,
			NETWORK_GRAPH_PERSISTENCE_KEY,
			&network_graph.encode(),
		)
	}

	fn persist_scorer(&self, scorer: &S) -> Result<(), io::Error> {
		if !self.persists_graph() {
			return Ok(());
		}
		self.kv_store.write(
			SCORER_PERSISTENCE_PRIMARY_NAMESPACE,
			SCORER_PERSISTENCE_SECONDARY_NAMESPACE,
			SCORER_PERSISTENCE_KEY,
			&scorer.encode(),
		)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use std::sync::Mutex;

	use bitcoin::Network;
	use lightning::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringDecayParameters};
	use lightning::util::test_utils::TestStore;

	use crate::logger::Logger;
	use crate::types::{ChannelManager, Graph, Scorer};

	/// A secondary's persister leaves the graph and scorer out of its store; a primary's
	/// writes both.
	#[test]
	fn only_an_own_graph_reaches_the_store() {
		let logger = Arc::new(Logger::new_log_facade());
		let graph = Arc::new(Graph::new(Network::Regtest, Arc::clone(&logger)));
		let scorer: Arc<Mutex<Scorer>> = Arc::new(Mutex::new(ProbabilisticScorer::new(
			ProbabilisticScoringDecayParameters::default(),
			Arc::clone(&graph),
			Arc::clone(&logger),
		)));

		for (graph_persistence, expect_written) in
			[(GraphPersistence::Shared, false), (GraphPersistence::Own, true)]
		{
			let kv_store: Arc<DynStore> = Arc::new(TestStore::new(false));
			let persister = BackgroundPersister::new(Arc::clone(&kv_store), graph_persistence);
			assert_eq!(persister.persists_graph(), expect_written);
			<BackgroundPersister as Persister<Arc<ChannelManager>, Arc<Logger>, Arc<Mutex<Scorer>>>>::persist_graph(
				&persister, &graph,
			)
			.unwrap();
			<BackgroundPersister as Persister<Arc<ChannelManager>, Arc<Logger>, Arc<Mutex<Scorer>>>>::persist_scorer(
				&persister, &scorer,
			)
			.unwrap();
			let graph_written = kv_store
				.read(
					NETWORK_GRAPH_PERSISTENCE_PRIMARY_NAMESPACE,
					NETWORK_GRAPH_PERSISTENCE_SECONDARY_NAMESPACE,
					NETWORK_GRAPH_PERSISTENCE_KEY,
				)
				.is_ok();
			let scorer_written = kv_store
				.read(
					SCORER_PERSISTENCE_PRIMARY_NAMESPACE,
					SCORER_PERSISTENCE_SECONDARY_NAMESPACE,
					SCORER_PERSISTENCE_KEY,
				)
				.is_ok();
			assert_eq!(graph_written, expect_written, "{:?}", graph_persistence);
			assert_eq!(scorer_written, expect_written, "{:?}", graph_persistence);
		}
	}
}
