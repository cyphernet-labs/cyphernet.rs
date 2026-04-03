// Set of libraries for privacy-preserving networking apps
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed and written in 2019-2026 by Dr. Maxim Orlovsky <orlovsky@cyphernet.io>
//
// Copyright 2022-2026 Cyphernet Labs, Institute for Distributed and Cognitive Computing.
// All rights reserved.
//
// Copyright (C) 2021-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations under
// the License.

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NymAddr([u8; 32]);

impl FromStr for NymAddr {
    type Err = ();

    fn from_str(_s: &str) -> Result<Self, Self::Err> { todo!() }
}

impl Display for NymAddr {
    fn fmt(&self, _f: &mut Formatter<'_>) -> fmt::Result { todo!() }
}
