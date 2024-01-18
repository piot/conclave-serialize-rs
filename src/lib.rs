/*----------------------------------------------------------------------------------------------------------
 *  Copyright (c) Peter Bjorklund. All rights reserved. https://github.com/piot/conclave-serialize-rs
 *  Licensed under the MIT License. See LICENSE in the project root for license information.
 *--------------------------------------------------------------------------------------------------------*/
//! The Conclave Protocol Serialization

use std::io::Cursor;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use conclave_room_serialize::{PingCommand, RoomInfoCommand};
use conclave_types::{ClientNonce, GuiseUserSessionId, SessionId};

use crate::ClientReceiveCommand::LoginResponseType;
use crate::ServerReceiveCommand::{LoginRequestType, PingCommandType};

/// Sent from Client to Server
#[derive(Debug, PartialEq)]
pub struct LoginRequest {
    pub guise_user_session_id: GuiseUserSessionId,
    pub nonce: ClientNonce,
}

impl LoginRequest {
    pub fn to_octets(&self) -> Vec<u8> {
        let mut writer = vec![];

        writer
            .write_u64::<BigEndian>(self.guise_user_session_id)
            .unwrap();
        writer.write_u64::<BigEndian>(self.nonce).unwrap();
        writer
    }

    pub fn from_cursor(reader: &mut Cursor<&[u8]>) -> Self {
        Self {
            guise_user_session_id: reader.read_u64::<BigEndian>().unwrap(),
            nonce: reader.read_u64::<BigEndian>().unwrap(),
        }
    }
}

#[derive(Debug)]
pub enum ServerReceiveCommand {
    LoginRequestType(LoginRequest),
    PingCommandType(PingCommand),
}

impl ServerReceiveCommand {
    pub fn to_octets(&self) -> Result<Vec<u8>, String> {
        let command_type_id = match self {
            LoginRequestType(_) => LOGIN_REQUEST_TYPE_ID,
            _ => return Err(format!("unsupported command {:?}", self)),
        };

        let mut writer = vec![];

        writer
            .write_u8(command_type_id)
            .expect("could not write command type id");

        match self {
            LoginRequestType(login_request) => {
                writer.extend_from_slice(login_request.to_octets().as_slice())
            }
            PingCommandType(ping_command) => {
                writer.extend_from_slice(ping_command.to_octets().as_slice())
            }
            // _ => return Err(format!("unknown command enum {:?}", self)),
        }

        Ok(writer)
    }

    pub fn from_octets(input: &[u8]) -> Result<ServerReceiveCommand, String> {
        let reader = Cursor::new(input);
        ServerReceiveCommand::from_cursor(reader)
    }

    pub fn from_cursor(mut reader: Cursor<&[u8]>) -> Result<ServerReceiveCommand, String> {
        let command_type_id = reader.read_u8().unwrap();
        match command_type_id {
            LOGIN_REQUEST_TYPE_ID => Ok(LoginRequestType(LoginRequest::from_cursor(&mut reader))),
            _ => Err(format!("unknown command 0x{:x}", command_type_id)),
        }
    }
}

/// Sent from Server to Client
#[derive(Debug)]
pub struct LoginResponse {
    pub nonce: ClientNonce,
    pub session_id: SessionId,
}

impl LoginResponse {
    pub fn to_octets(&self) -> Vec<u8> {
        let mut writer = vec![];

        writer
            .write_u64::<BigEndian>(self.nonce)
            .unwrap();
        writer.write_u64::<BigEndian>(self.session_id).unwrap();
        writer
    }

    pub fn from_cursor(reader: &mut Cursor<&[u8]>) -> Self {
        Self {
            nonce: reader.read_u64::<BigEndian>().unwrap(),
            session_id: reader.read_u64::<BigEndian>().unwrap(),
        }
    }
}

#[derive(Debug)]
pub enum ClientReceiveCommand {
    LoginResponseType(LoginResponse),
    RoomInfoType(RoomInfoCommand),
}

pub const LOGIN_REQUEST_TYPE_ID: u8 = 0x02;
pub const LOGIN_RESPONSE_TYPE_ID: u8 = 0x22;

impl ClientReceiveCommand {
    pub fn to_octets(&self) -> Result<Vec<u8>, String> {
        let command_type_id = match self {
            LoginResponseType(_) => LOGIN_RESPONSE_TYPE_ID,
            _ => return Err(format!("unsupported command {:?}", self)),
        };

        let mut writer = vec![];

        writer
            .write_u8(command_type_id)
            .expect("could not write command type id");

        match self {
            LoginResponseType(login_response) => {
                writer.extend_from_slice(login_response.to_octets().as_slice())
            }
            _ => return Err(format!("unknown command enum {:?}", self)),
        }

        Ok(writer)
    }

    pub fn from_octets(input: &[u8]) -> Result<ClientReceiveCommand, String> {
        let mut rdr = Cursor::new(input);
        let command_type_id = rdr.read_u8().unwrap();
        match command_type_id {
            LOGIN_RESPONSE_TYPE_ID => Ok(LoginResponseType(LoginResponse::from_cursor(&mut rdr))),
            _ => Err(format!("unknown command 0x{:x}", command_type_id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::{ClientReceiveCommand, LOGIN_REQUEST_TYPE_ID, LOGIN_RESPONSE_TYPE_ID, LoginRequest, LoginResponseType, ServerReceiveCommand};
    use crate::ServerReceiveCommand::LoginRequestType;

    #[test]
    fn check_login_request_serializer() {
        let login_request = LoginRequest {
            guise_user_session_id: 4214124,
            nonce: 19,
        };

        let encoded = login_request.to_octets();
        let mut receive_cursor = Cursor::new(encoded.as_slice());
        let deserialized_ping_command = LoginRequest::from_cursor(&mut receive_cursor);

        println!("before {:?}", &login_request);
        println!("after {:?}", &deserialized_ping_command);
        assert_eq!(login_request, deserialized_ping_command);
    }

    #[test]
    fn check_server_receive_login_request() {
        let octets = [
            LOGIN_REQUEST_TYPE_ID,
            0x00, // guise user session id
            0x00,
            0x00,
            0x00,
            0x00,
            0x40,
            0x4d,
            0x6c,
            0x00, // nonce
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x13,
        ];

        let message = &ServerReceiveCommand::from_octets(&octets).unwrap();

        match message {
            LoginRequestType(login_request) => {
                println!("received {:?}", &login_request);
                assert_eq!(login_request.guise_user_session_id, 4214124);
                assert_eq!(login_request.nonce, 19);
                let octets_after = message.to_octets().unwrap();
                assert_eq!(octets, octets_after.as_slice());
            }
            _ => unreachable!("should be login request command"),
        }
    }

    #[test]
    fn check_client_receive_message() {
        let octets = [
            LOGIN_RESPONSE_TYPE_ID,
            0x00, // Nonce
            0x00,
            0x00,
            0x09,
            0xC6,
            0x36,
            0xCD,
            0x41,
            0x00, // session id
            0x00,
            0x00,
            0x00,
            0x3B,
            0x4B,
            0xB9,
            0x6A,
        ];

        let message = &ClientReceiveCommand::from_octets(&octets).unwrap();

        match message {
            LoginResponseType(login_response) => {
                println!("received {:?}", &login_response);
                assert_eq!(login_response.nonce, 41980185921);
                assert_eq!(login_response.session_id, 994818410);
                let octets_after = message.to_octets().unwrap();
                assert_eq!(octets, octets_after.as_slice());
            }
            _ => unreachable!("should be room info command"),
        }
    }
}
