// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! The process-level network surface shared by the nodes in it: the TCP listener, the overlay
//! (Lightning over the Node's own QUIC network), and the act-one door both route through.
//! The transport itself — streams, dialing, the BOLT 8 act-one demux, LDK's `SocketDescriptor`
//! — lives in `node-net` / `node-net-ldk` (node-net ADR 0001).

pub(crate) mod listener;
pub(crate) mod overlay;
pub(crate) mod target;
