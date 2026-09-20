// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Concrete chain ability adapters.
//!
//! One module per backend. Each fills whichever slots that backend can serve;
//! nothing here knows about node kinds, tiers or presets.

pub(crate) mod bitcoind;
pub(crate) mod electrum;
pub(crate) mod esplora;
