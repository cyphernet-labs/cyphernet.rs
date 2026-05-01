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

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
#[repr(u8)]
#[non_exhaustive]
pub enum ServerError {
    /// general SOCKS server failure
    GeneralFailure = 1,
    /// connection not allowed by ruleset
    NotAllowed = 2,
    /// network unreachable
    NetworkUnreachable = 3,
    /// host unreachable
    HostUnreachable = 4,
    /// connection refused
    ConnectionRefused = 5,
    /// TTL expired
    TtlExpired = 6,
    /// command not supported
    CommandNotSupported = 7,
    /// address kind not supported
    AddressNotSupported = 8,
    /// onion service descriptor can not be found
    HsDescNotFound = 0xF0,
    /// onion service descriptor is invalid
    HsDescInvalid = 0xF1,
    /// onion service introduction failed
    HsIntroFailed = 0xF2,
    /// onion service rendezvous failed
    HsRendFailed = 0xF3,
    /// onion service missing client authorization
    HsMissingClientAuth = 0xF4,
    /// onion service wrong client authorization
    HsWrongClientAuth = 0xF5,
    /// onion service address is invalid
    HsBadAddress = 0xF6,
    /// onion service introduction timed out
    HsIntroTimeout = 0xF7,

    /// unknown error type
    Unknown = 0xFF,
}

impl From<u8> for ServerError {
    fn from(value: u8) -> Self {
        const ALL: [ServerError; 16] = [
            ServerError::GeneralFailure,
            ServerError::NotAllowed,
            ServerError::NetworkUnreachable,
            ServerError::HostUnreachable,
            ServerError::ConnectionRefused,
            ServerError::TtlExpired,
            ServerError::CommandNotSupported,
            ServerError::AddressNotSupported,
            ServerError::HsDescNotFound,
            ServerError::HsDescInvalid,
            ServerError::HsIntroFailed,
            ServerError::HsRendFailed,
            ServerError::HsMissingClientAuth,
            ServerError::HsWrongClientAuth,
            ServerError::HsBadAddress,
            ServerError::HsIntroTimeout,
        ];

        for ty in ALL {
            if ty as u8 == value {
                return ty;
            }
        }

        ServerError::Unknown
    }
}
