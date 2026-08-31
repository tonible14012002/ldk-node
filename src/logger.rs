// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Logging-related objects.

pub(crate) use lightning::util::logger::{Logger as LdkLogger, Record as LdkRecord};
pub(crate) use lightning::{log_bytes, log_debug, log_error, log_info, log_trace};

pub use lightning::util::logger::Level as LogLevel;

use chrono::Utc;
use log::Level as LogFacadeLevel;
use log::Record as LogFacadeRecord;

#[cfg(not(feature = "uniffi"))]
use core::fmt;
use std::fs;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A unit of logging output with metadata to enable filtering `module_path`,
/// `file`, and `line` to inform on log's source.
#[cfg(not(feature = "uniffi"))]
pub struct LogRecord<'a> {
	/// The verbosity level of the message.
	pub level: LogLevel,
	/// The message body.
	pub args: fmt::Arguments<'a>,
	/// The module path of the message.
	pub module_path: &'a str,
	/// The line containing the message.
	pub line: u32,
}

/// A unit of logging output with metadata to enable filtering `module_path`,
/// `file`, and `line` to inform on log's source.
///
/// This version is used when the `uniffi` feature is enabled.
/// It is similar to the non-`uniffi` version, but it omits the lifetime parameter
/// for the `LogRecord`, as the Uniffi-exposed interface cannot handle lifetimes.
#[cfg(feature = "uniffi")]
pub struct LogRecord {
	/// The verbosity level of the message.
	pub level: LogLevel,
	/// The message body.
	pub args: String,
	/// The module path of the message.
	pub module_path: String,
	/// The line containing the message.
	pub line: u32,
}

#[cfg(feature = "uniffi")]
impl<'a> From<LdkRecord<'a>> for LogRecord {
	fn from(record: LdkRecord) -> Self {
		Self {
			level: record.level,
			args: record.args.to_string(),
			module_path: record.module_path.to_string(),
			line: record.line,
		}
	}
}

#[cfg(not(feature = "uniffi"))]
impl<'a> From<LdkRecord<'a>> for LogRecord<'a> {
	fn from(record: LdkRecord<'a>) -> Self {
		Self {
			level: record.level,
			args: record.args,
			module_path: record.module_path,
			line: record.line,
		}
	}
}

/// Defines the behavior required for writing log records.
///
/// Implementors of this trait are responsible for handling log messages,
/// which may involve formatting, filtering, and forwarding them to specific
/// outputs.
#[cfg(not(feature = "uniffi"))]
pub trait LogWriter: Send + Sync {
	/// Log the record.
	fn log<'a>(&self, record: LogRecord<'a>);
}

/// Defines the behavior required for writing log records.
///
/// Implementors of this trait are responsible for handling log messages,
/// which may involve formatting, filtering, and forwarding them to specific
/// outputs.
/// This version is used when the `uniffi` feature is enabled.
/// It is similar to the non-`uniffi` version, but it omits the lifetime parameter
/// for the `LogRecord`, as the Uniffi-exposed interface cannot handle lifetimes.
#[cfg(feature = "uniffi")]
pub trait LogWriter: Send + Sync {
	/// Log the record.
	fn log(&self, record: LogRecord);
}

/// How long a buffered record may sit unwritten before the next record forces a
/// flush. Bounds how much of the tail is lost if the process dies without
/// paying a syscall per line.
const LOG_FLUSH_INTERVAL: Duration = Duration::from_secs(5);

/// Capacity of the buffer held in front of the log file.
const LOG_BUFFER_BYTES: usize = 16 * 1024;

/// The log file behind [`Writer::FileWriter`], held open and buffered across
/// records rather than reopened for each one.
///
/// The handle is opened in append mode, so it stays correct across a
/// `copytruncate` rotation: writes continue at the new end of the same inode.
/// Rotation that *renames* the file would leave this handle attached to the
/// rotated copy, so the packaged logrotate rule must keep using `copytruncate`.
pub(crate) struct FileSink {
	sink: Option<BufWriter<fs::File>>,
	dropped_records: u64,
	last_flush: Instant,
}

impl FileSink {
	fn new() -> Self {
		Self { sink: None, dropped_records: 0, last_flush: Instant::now() }
	}

	/// Writes one already-formatted record.
	///
	/// Logging must never take the node down, so an I/O failure here is counted
	/// and reported with the next record that gets through instead of being
	/// propagated or panicked on.
	fn write_record(&mut self, file_path: &str, level: LogLevel, record: &str) {
		if !self.ensure_open(file_path) {
			self.dropped_records = self.dropped_records.saturating_add(1);
			return;
		}

		if let Some(notice) = self.take_dropped_notice() {
			let _ = self.write_bytes(notice.as_bytes());
		}

		if self.write_bytes(record.as_bytes()).is_err() {
			// Drop the handle so the next record reopens the file.
			self.sink = None;
			self.dropped_records = self.dropped_records.saturating_add(1);
			return;
		}

		if level >= LogLevel::Warn || self.last_flush.elapsed() >= LOG_FLUSH_INTERVAL {
			self.flush();
		}
	}

	fn ensure_open(&mut self, file_path: &str) -> bool {
		if self.sink.is_some() {
			return true;
		}

		match fs::OpenOptions::new().create(true).append(true).open(file_path) {
			Ok(file) => {
				self.sink = Some(BufWriter::with_capacity(LOG_BUFFER_BYTES, file));
				true
			},
			Err(_) => false,
		}
	}

	fn write_bytes(&mut self, bytes: &[u8]) -> std::io::Result<()> {
		match self.sink.as_mut() {
			Some(sink) => sink.write_all(bytes),
			None => {
				Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "log file is not open"))
			},
		}
	}

	/// Renders a record accounting for anything lost while the file was
	/// unwritable, so a silent gap in the log is never silent.
	fn take_dropped_notice(&mut self) -> Option<String> {
		if self.dropped_records == 0 {
			return None;
		}

		let dropped = self.dropped_records;
		self.dropped_records = 0;
		Some(format!(
			"{} {:<5} [{}:{}] dropped {} log records: the log file could not be written\n",
			Utc::now().format("%Y-%m-%d %H:%M:%S"),
			LogLevel::Warn.to_string(),
			module_path!(),
			line!(),
			dropped
		))
	}

	fn flush(&mut self) {
		if let Some(sink) = self.sink.as_mut() {
			if sink.flush().is_err() {
				self.sink = None;
				return;
			}
		}
		self.last_flush = Instant::now();
	}
}

impl Drop for FileSink {
	fn drop(&mut self) {
		self.flush();
	}
}

/// Defines a writer for [`Logger`].
pub(crate) enum Writer {
	/// Writes logs to the file system.
	FileWriter { file_path: String, max_log_level: LogLevel, sink: Mutex<FileSink> },
	/// Forwards logs to the `log` facade.
	LogFacadeWriter,
	/// Forwards logs to a custom writer.
	CustomWriter(Arc<dyn LogWriter>),
}

impl LogWriter for Writer {
	fn log(&self, record: LogRecord) {
		match self {
			Writer::FileWriter { file_path, max_log_level, sink } => {
				if record.level < *max_log_level {
					return;
				}

				let log = format!(
					"{} {:<5} [{}:{}] {}\n",
					Utc::now().format("%Y-%m-%d %H:%M:%S"),
					record.level.to_string(),
					record.module_path,
					record.line,
					record.args
				);

				let mut sink_lock = sink.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
				sink_lock.write_record(file_path, record.level, &log);
			},
			Writer::LogFacadeWriter => {
				let mut builder = LogFacadeRecord::builder();

				match record.level {
					LogLevel::Gossip | LogLevel::Trace => builder.level(LogFacadeLevel::Trace),
					LogLevel::Debug => builder.level(LogFacadeLevel::Debug),
					LogLevel::Info => builder.level(LogFacadeLevel::Info),
					LogLevel::Warn => builder.level(LogFacadeLevel::Warn),
					LogLevel::Error => builder.level(LogFacadeLevel::Error),
				};

				#[cfg(not(feature = "uniffi"))]
				log::logger().log(
					&builder
						.target(record.module_path)
						.module_path(Some(record.module_path))
						.line(Some(record.line))
						.args(format_args!("{}", record.args))
						.build(),
				);
				#[cfg(feature = "uniffi")]
				log::logger().log(
					&builder
						.target(&record.module_path)
						.module_path(Some(&record.module_path))
						.line(Some(record.line))
						.args(format_args!("{}", record.args))
						.build(),
				);
			},
			Writer::CustomWriter(custom_logger) => custom_logger.log(record),
		}
	}
}

/// A logger for LDK Node that can write to files, the log facade, or custom writers.
pub struct Logger {
	/// Specifies the logger's writer.
	writer: Writer,
}

impl Logger {
	/// Creates a new logger with a filesystem writer. The parameters to this function
	/// are the path to the log file, and the log level.
	pub fn new_fs_writer(file_path: String, max_log_level: LogLevel) -> Result<Self, ()> {
		if let Some(parent_dir) = Path::new(&file_path).parent() {
			fs::create_dir_all(parent_dir)
				.map_err(|e| eprintln!("ERROR: Failed to create log parent directory: {}", e))?;

			// make sure the file exists.
			fs::OpenOptions::new()
				.create(true)
				.append(true)
				.open(&file_path)
				.map_err(|e| eprintln!("ERROR: Failed to open log file: {}", e))?;
		}

		Ok(Self {
			writer: Writer::FileWriter {
				file_path,
				max_log_level,
				sink: Mutex::new(FileSink::new()),
			},
		})
	}

	/// Creates a new logger that forwards logs to the `log` facade.
	pub fn new_log_facade() -> Self {
		Self { writer: Writer::LogFacadeWriter }
	}

	/// Creates a new logger with a custom writer.
	pub fn new_custom_writer(log_writer: Arc<dyn LogWriter>) -> Self {
		Self { writer: Writer::CustomWriter(log_writer) }
	}
}

impl LdkLogger for Logger {
	fn log(&self, record: LdkRecord) {
		match &self.writer {
			Writer::FileWriter { max_log_level, .. } => {
				if record.level < *max_log_level {
					return;
				}
				self.writer.log(record.into());
			},
			Writer::LogFacadeWriter => {
				self.writer.log(record.into());
			},
			Writer::CustomWriter(_arc) => {
				self.writer.log(record.into());
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::atomic::{AtomicUsize, Ordering};

	fn temp_log_path(tag: &str) -> String {
		static COUNTER: AtomicUsize = AtomicUsize::new(0);
		let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
		std::env::temp_dir()
			.join(format!("ldk-node-logger-{}-{}-{}.log", tag, std::process::id(), unique))
			.to_string_lossy()
			.into_owned()
	}

	fn read(path: &str) -> String {
		fs::read_to_string(path).unwrap_or_default()
	}

	#[test]
	fn buffers_until_a_serious_record_forces_a_flush() {
		let path = temp_log_path("buffering");
		let mut sink = FileSink::new();

		sink.write_record(&path, LogLevel::Debug, "debug line\n");
		assert_eq!(read(&path), "", "a debug record should still be buffered");

		sink.write_record(&path, LogLevel::Error, "error line\n");
		assert_eq!(
			read(&path),
			"debug line\nerror line\n",
			"an error record must flush what is buffered behind it"
		);

		let _ = fs::remove_file(&path);
	}

	#[test]
	fn keeps_writing_after_the_file_is_truncated_in_place() {
		let path = temp_log_path("copytruncate");
		let mut sink = FileSink::new();

		sink.write_record(&path, LogLevel::Error, "before rotation\n");
		assert_eq!(read(&path), "before rotation\n");

		// Exactly what `logrotate ... copytruncate` does: same inode, zero length.
		fs::OpenOptions::new().write(true).truncate(true).open(&path).unwrap();
		assert_eq!(read(&path), "");

		sink.write_record(&path, LogLevel::Error, "after rotation\n");
		assert_eq!(
			read(&path),
			"after rotation\n",
			"the held handle must follow a copytruncate rotation"
		);

		let _ = fs::remove_file(&path);
	}

	#[test]
	fn counts_unwritable_records_and_reports_them_once_writing_recovers() {
		let unwritable = format!("{}/does-not-exist/ldk_node.log", temp_log_path("unwritable"));
		let mut sink = FileSink::new();

		sink.write_record(&unwritable, LogLevel::Error, "lost line\n");
		assert_eq!(sink.dropped_records, 1, "a failed open must be counted, not panic");

		let path = temp_log_path("recovery");
		sink.write_record(&path, LogLevel::Error, "kept line\n");

		let written = read(&path);
		assert!(
			written.contains("dropped 1 log records"),
			"the gap must be reported once writing recovers, got: {}",
			written
		);
		assert!(written.ends_with("kept line\n"));
		assert_eq!(sink.dropped_records, 0);

		let _ = fs::remove_file(&path);
	}
}
