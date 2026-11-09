// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! The chain layer is `node-chain`'s; this is what the node keeps to plug into it.
//!
//! `node-chain` follows Bitcoin for the node's wallet and Lightning objects through the
//! `node-chain-seam` traits, and `node-chain-ldk` hands LDK's chain traits across that seam
//! both ways. What is left here is what only the node knows: its logger as the chain layer's
//! log, its wallet as a [`ChainWallet`](node_chain_seam::ChainWallet) (in [`wallet`]), what a
//! sync pass writes back into the node ([`observer`]), the error and configuration
//! conversions, and the public [`ChainHost`]/[`ChainHostBuilder`] (in [`host`]), which keep
//! the shape they had when the layer lived in this crate.

pub(crate) mod host;
pub(crate) mod observer;
pub(crate) mod wallet;

// The provider-session tests that run a real Node on a host over a session; the session's
// node-free tests are node-chain's.
#[cfg(all(test, feature = "cbf"))]
mod session_tests;

pub use host::{ChainHost, ChainHostBuilder};

pub(crate) use node_chain::{ChainLayer, ChainTargetSpec, TargetId};

use crate::config::Config;
use crate::logger::{LdkLogger, LdkRecord, LogLevel, Logger};
use crate::Error;

use node_chain::config::ChainConfig;
use node_chain_seam::{ChainError, ChainLog, LogRecord};

/// The chain layer logs into the node's log, as it did inside this crate.
impl ChainLog for Logger {
	fn log(&self, record: LogRecord<'_>) {
		let level = match record.level {
			node_chain_seam::LogLevel::Trace => LogLevel::Trace,
			node_chain_seam::LogLevel::Debug => LogLevel::Debug,
			node_chain_seam::LogLevel::Info => LogLevel::Info,
			node_chain_seam::LogLevel::Warn => LogLevel::Warn,
			node_chain_seam::LogLevel::Error => LogLevel::Error,
		};
		LdkLogger::log(
			self,
			LdkRecord::new(
				level,
				None,
				None,
				record.args,
				record.module_path,
				record.file,
				record.line,
				None,
			),
		)
	}
}

/// Every chain-layer error is one of this crate's, with the same meaning.
impl From<ChainError> for Error {
	fn from(e: ChainError) -> Self {
		match e {
			ChainError::NotRunning => Error::NotRunning,
			ChainError::ConnectionFailed => Error::ConnectionFailed,
			ChainError::InvalidSocketAddress => Error::InvalidSocketAddress,
			ChainError::PersistenceFailed => Error::PersistenceFailed,
			ChainError::FeerateEstimationUpdateFailed => Error::FeerateEstimationUpdateFailed,
			ChainError::FeerateEstimationUpdateTimeout => Error::FeerateEstimationUpdateTimeout,
			ChainError::WalletOperationFailed => Error::WalletOperationFailed,
			ChainError::WalletOperationTimeout => Error::WalletOperationTimeout,
			ChainError::TxSyncFailed => Error::TxSyncFailed,
			ChainError::TxSyncTimeout => Error::TxSyncTimeout,
			ChainError::GossipUpdateTimeout => Error::GossipUpdateTimeout,
			ChainError::ChainServeUnsupported => Error::ChainServeUnsupported,
			ChainError::ChainServeFailed => Error::ChainServeFailed,
			ChainError::ChainServeNotOnBestChain => Error::ChainServeNotOnBestChain,
		}
	}
}

/// The node's errors the chain layer's callbacks into the node return. Only the variants the
/// node's side of the seam produces are ever passed; any other is a wallet operation failing.
pub(crate) fn chain_error(e: Error) -> ChainError {
	match e {
		Error::NotRunning => ChainError::NotRunning,
		Error::ConnectionFailed => ChainError::ConnectionFailed,
		Error::InvalidSocketAddress => ChainError::InvalidSocketAddress,
		Error::PersistenceFailed => ChainError::PersistenceFailed,
		Error::FeerateEstimationUpdateFailed => ChainError::FeerateEstimationUpdateFailed,
		Error::FeerateEstimationUpdateTimeout => ChainError::FeerateEstimationUpdateTimeout,
		Error::WalletOperationFailed => ChainError::WalletOperationFailed,
		Error::WalletOperationTimeout => ChainError::WalletOperationTimeout,
		Error::TxSyncFailed => ChainError::TxSyncFailed,
		Error::TxSyncTimeout => ChainError::TxSyncTimeout,
		Error::GossipUpdateTimeout => ChainError::GossipUpdateTimeout,
		Error::ChainServeUnsupported => ChainError::ChainServeUnsupported,
		Error::ChainServeFailed => ChainError::ChainServeFailed,
		Error::ChainServeNotOnBestChain => ChainError::ChainServeNotOnBestChain,
		_ => ChainError::WalletOperationFailed,
	}
}

/// The two fields of the node's configuration the chain layer reads.
impl From<&Config> for ChainConfig {
	fn from(config: &Config) -> Self {
		ChainConfig { network: config.network, storage_dir_path: config.storage_dir_path.clone() }
	}
}

impl From<Config> for ChainConfig {
	fn from(config: Config) -> Self {
		ChainConfig::from(&config)
	}
}
