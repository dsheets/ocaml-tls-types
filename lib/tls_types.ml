(*
 * Copyright (c) 2014 David Sheets <sheets@alum.mit.edu>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *)

open Ctypes

module X509 = struct (* TODO: another package... *)
  type certificate = unit ptr
end

module Openssl = struct
  module Basic = struct

    (* constants from openssl-1.0.1f *)
    type ssl_error =
    | SSL_ERROR_ZERO_RETURN
    | SSL_ERROR_WANT_READ
    | SSL_ERROR_WANT_WRITE
    | SSL_ERROR_WANT_CONNECT
    | SSL_ERROR_WANT_ACCEPT
    | SSL_ERROR_WANT_X509_LOOKUP
    | SSL_ERROR_SYSCALL
    | SSL_ERROR_SSL

    exception SSLError of ssl_error
    exception SSLFatalError of ssl_error

    type ssl_filetype =
    | SSL_FILETYPE_PEM
    | SSL_FILETYPE_ASN1

    type ssl_verify_peer_mode =
    | SSL_VERIFY_FAIL_IF_NO_PEER_CERT
    | SSL_VERIFY_CLIENT_ONCE

    type ssl_verify_mode =
    | SSL_VERIFY_NONE
    | SSL_VERIFY_PEER of ssl_verify_peer_mode list

    type ssl_state =
    | SSL_ST_CONNECT
    | SSL_ST_ACCEPT
    (* SSL_ST_MASK? *)
    | SSL_ST_INIT
    | SSL_ST_BEFORE
    | SSL_ST_OK
    | SSL_ST_RENEGOTIATE

    type ssl_verify_error =
    | X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
    | X509_V_ERR_UNABLE_TO_GET_CRL
    | X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE
    | X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE
    | X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY
    | X509_V_ERR_CERT_SIGNATURE_FAILURE
    | X509_V_ERR_CRL_SIGNATURE_FAILURE
    | X509_V_ERR_CERT_NOT_YET_VALID
    | X509_V_ERR_CERT_HAS_EXPIRED
    | X509_V_ERR_CRL_NOT_YET_VALID
    | X509_V_ERR_CRL_HAS_EXPIRED
    | X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD
    | X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD
    | X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD
    | X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD
    | X509_V_ERR_OUT_OF_MEM
    | X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
    | X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
    | X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
    | X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
    | X509_V_ERR_CERT_CHAIN_TOO_LONG
    | X509_V_ERR_CERT_REVOKED
    | X509_V_ERR_INVALID_CA
    | X509_V_ERR_PATH_LENGTH_EXCEEDED
    | X509_V_ERR_INVALID_PURPOSE
    | X509_V_ERR_CERT_UNTRUSTED
    | X509_V_ERR_CERT_REJECTED
    | X509_V_ERR_SUBJECT_ISSUER_MISMATCH
    | X509_V_ERR_AKID_SKID_MISMATCH
    | X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH
    | X509_V_ERR_KEYUSAGE_NO_CERTSIGN
    | X509_V_ERR_APPLICATION_VERIFICATION

  end

  module Bindings(F : sig
    include Cstubs.FOREIGN

    type x509_store_ctx

    val x509_store_ctx : x509_store_ctx typ
  end) =
  struct
    module Basic = struct
      open F
      type x509_store_ctx = F.x509_store_ctx
      let x509_store_ctx = F.x509_store_ctx

      type verify_callback_t = int -> F.x509_store_ctx -> int
      type verify_callback = verify_callback_t fn

      let verify_callback : verify_callback_t Ctypes.fn =
        int @-> F.x509_store_ctx @-> returning int

      let verify_callback_p : verify_callback Ctypes.typ = funptr verify_callback

      let ssl_hdr = `Include "<openssl/ssl.h>"

      (* constants from openssl-1.0.1f *)
      let ssl_error : Basic.ssl_error option Ctypes.typ = F.Enum.(
        macro
          ~from:[ssl_hdr]
          ~type_name:"ssl_error"
          ~use_module:"Tls_types.Openssl.Basic"
          ~default:"SSL_ERROR_NONE"
          int
          (one [
            require "SSL_ERROR_ZERO_RETURN";
            require "SSL_ERROR_WANT_READ";
            require "SSL_ERROR_WANT_WRITE";
            require "SSL_ERROR_WANT_CONNECT";
            require "SSL_ERROR_WANT_ACCEPT";
            require "SSL_ERROR_WANT_X509_LOOKUP";
            require "SSL_ERROR_SYSCALL";
            require "SSL_ERROR_SSL";
          ])
      )

      let ssl_filetype : Basic.ssl_filetype Ctypes.typ = F.Enum.(
        macro
          ~from:[ssl_hdr]
          ~type_name:"ssl_filetype"
          ~use_module:"Tls_types.Openssl.Basic"
          int
          (one [
            require "SSL_FILETYPE_PEM";
            require "SSL_FILETYPE_ASN1";
          ])
      )

      let ssl_verify_peer_mode : Basic.ssl_verify_peer_mode list Ctypes.typ =
        F.Enum.(
          macro
            ~from:[ssl_hdr]
            ~type_name:"ssl_verify_peer_mode"
            ~use_module:"Tls_types.Openssl.Basic"
            int
            (any [
              require "SSL_VERIFY_FAIL_IF_NO_PEER_CERT";
              require "SSL_VERIFY_CLIENT_ONCE";
            ])
        )

      let ssl_verify_mode : Basic.ssl_verify_mode Ctypes.typ = F.Enum.(
        macro
          ~from:[ssl_hdr]
          ~type_name:"ssl_verify_mode"
          ~use_module:"Tls_types.Openssl.Basic"
          int
          (one [
            require "SSL_VERIFY_NONE";
            require_bits "ssl_verify_peer_mode" "SSL_VERIFY_PEER";
          ])
      )

      let ssl_state : Basic.ssl_state list Ctypes.typ = F.Enum.(
        macro
          ~from:[ssl_hdr]
          ~type_name:"ssl_state"
          ~use_module:"Tls_types.Openssl.Basic"
          int
          (any [
            require "SSL_ST_CONNECT";
            require "SSL_ST_ACCEPT";
            require "SSL_ST_INIT";
            require "SSL_ST_BEFORE";
            require "SSL_ST_OK";
            require "SSL_ST_RENEGOTIATE";
          ])
      )

      let ssl_verify_error_opt : Basic.ssl_verify_error option Ctypes.typ =
        F.Enum.(
          macro
            ~from:[ssl_hdr]
            ~type_name:"ssl_verify_error"
            ~use_module:"Tls_types.Openssl.Basic"
            ~default:"X509_V_OK"
            int
            (one [
              require "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT";
              require "X509_V_ERR_UNABLE_TO_GET_CRL";
              require "X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE";
              require "X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE";
              require "X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY";
              require "X509_V_ERR_CERT_SIGNATURE_FAILURE";
              require "X509_V_ERR_CRL_SIGNATURE_FAILURE";
              require "X509_V_ERR_CERT_NOT_YET_VALID";
              require "X509_V_ERR_CERT_HAS_EXPIRED";
              require "X509_V_ERR_CRL_NOT_YET_VALID";
              require "X509_V_ERR_CRL_HAS_EXPIRED";
              require "X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD";
              require "X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD";
              require "X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD";
              require "X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD";
              require "X509_V_ERR_OUT_OF_MEM";
              require "X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT";
              require "X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN";
              require "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY";
              require "X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE";
              require "X509_V_ERR_CERT_CHAIN_TOO_LONG";
              require "X509_V_ERR_CERT_REVOKED";
              require "X509_V_ERR_INVALID_CA";
              require "X509_V_ERR_PATH_LENGTH_EXCEEDED";
              require "X509_V_ERR_INVALID_PURPOSE";
              require "X509_V_ERR_CERT_UNTRUSTED";
              require "X509_V_ERR_CERT_REJECTED";
              require "X509_V_ERR_SUBJECT_ISSUER_MISMATCH";
              require "X509_V_ERR_AKID_SKID_MISMATCH";
              require "X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH";
              require "X509_V_ERR_KEYUSAGE_NO_CERTSIGN";
              require "X509_V_ERR_APPLICATION_VERIFICATION";
            ])
        )
    end
  end

  module type BASIC_COMMON = sig
    open Basic

    type 'a fn

    type ssl_method
    type ssl_ctx
    type ssl
    type ssl_session

    type bio

    type x509_store_ctx
    type stack_of_x509_names

    type verify_callback_t = int -> x509_store_ctx -> int
    type verify_callback = verify_callback_t fn
    type pem_password_cb_t = char ptr -> int -> bool -> unit ptr -> int
    type pem_password_cb = pem_password_cb_t fn

    val x509_store_ctx    : x509_store_ctx typ
    val verify_callback   : verify_callback_t Ctypes.fn
    val verify_callback_p : verify_callback typ

    val pem_password_cb   : pem_password_cb_t Ctypes.fn
    val pem_password_cb_p : pem_password_cb typ

    val sslv23_server_method : ssl_method
    val sslv3_server_method  : ssl_method
    val tlsv1_server_method  : ssl_method
    val sslv23_client_method : ssl_method
    val sslv3_client_method  : ssl_method
    val tlsv1_client_method  : ssl_method

    val ssl_load_error_strings : (unit -> unit) fn

    val ssl_ctx_new : (ssl_method -> ssl_ctx) fn
    val ssl_ctx_free : (ssl_ctx -> unit) fn

    val ssl_ctx_set_verify :
      (ssl_ctx -> ssl_verify_mode -> verify_callback -> unit) fn
    val ssl_ctx_set_verify_depth : (ssl_ctx -> int -> unit) fn

    val ssl_load_client_ca_file : (string -> stack_of_x509_names) fn
    val ssl_ctx_set_client_ca_list : (ssl_ctx -> stack_of_x509_names -> unit) fn
    val ssl_ctx_set_default_passwd_cb : (ssl_ctx -> pem_password_cb -> unit) fn
    val ssl_ctx_set_default_passwd_cd_userdata : (ssl_ctx -> unit ptr -> unit) fn

    val ssl_ctx_set_cipher_list : (ssl_ctx -> string -> bool) fn
    (* TODO: cipher list data type *)
    val ssl_ctx_set_options : (ssl_ctx -> int32 -> int32) fn
    (* TODO: options data type *)
    val ssl_new : (ssl_ctx -> ssl) fn

    val ssl_free : (ssl -> unit) fn
    val ssl_read : (ssl -> unit ptr -> int -> int) fn
    val ssl_write : (ssl -> unit ptr -> int -> int) fn
    val ssl_shutdown : (ssl -> bool) fn
    val ssl_peek : (ssl -> unit ptr -> int -> int) fn

    val ssl_get_verify_result : (ssl -> ssl_verify_error option) fn
    val ssl_state : (ssl -> ssl_state list) fn
    val ssl_get_peer_certificate : (ssl -> X509.certificate option) fn

    val ssl_get_error : (ssl -> int -> ssl_error option) fn
    val ssl_get1_session : (ssl -> ssl_session) fn

    val ssl_session_free : (ssl_session -> unit) fn
  end

  module type BASIC_C = sig
    open Basic

    include BASIC_COMMON

    val ssl_library_init : (unit -> int) fn

    val ssl_ctx_use_certificate_file :
      (ssl_ctx -> string -> ssl_filetype -> int) fn
    val ssl_ctx_use_privatekey_file :
      (ssl_ctx -> string -> ssl_filetype -> int) fn
    val ssl_ctx_use_certificate_asn1 :
      (ssl_ctx -> int -> Unsigned.uint8 ptr -> int) fn
    val ssl_ctx_set_session_id_context : (ssl_ctx -> string -> int -> int) fn
    val ssl_ctx_set_default_verify_paths : (ssl_ctx -> int) fn
    val ssl_ctx_use_certificate_chain_file : (ssl_ctx -> string -> int) fn

    val ssl_ctx_load_verify_locations :
      (ssl_ctx -> string option -> string option -> int) fn

    val ssl_ctx_check_private_key : (ssl_ctx -> int) fn

    val ssl_set_fd : (ssl -> Unix.file_descr -> int) fn
    val ssl_accept : (ssl -> int) fn
    val ssl_connect : (ssl -> int) fn

    val ssl_set_bio : (ssl -> bio -> bio -> unit) fn

    val ssl_clear : (ssl -> int) fn

    val ssl_set_session : (ssl -> ssl_session -> int) fn
  end

  module type BASIC = sig
    open Basic

    include BASIC_COMMON with type 'a fn = 'a

    val ssl_library_init : unit -> unit

    val ssl_ctx_use_certificate_file : ssl_ctx -> string -> ssl_filetype -> unit
    val ssl_ctx_use_privatekey_file : ssl_ctx -> string -> ssl_filetype -> unit
    val ssl_ctx_use_certificate_asn1 :
      ssl_ctx -> Unsigned.uint8 ptr -> int -> unit
    val ssl_ctx_set_session_id_context : ssl_ctx -> string -> int -> unit
    val ssl_ctx_set_default_verify_paths : ssl_ctx -> unit
    val ssl_ctx_use_certificate_chain_file : ssl_ctx -> string -> unit

    val ssl_ctx_load_verify_locations :
      ssl_ctx -> ?cafile:string -> ?capath:string -> unit -> unit

    val ssl_ctx_check_private_key : ssl_ctx -> unit

    val ssl_set_fd : ssl -> Unix.file_descr -> unit
    val ssl_accept : ssl -> unit
    val ssl_connect : ssl -> unit

    val ssl_set_bio : ssl -> rbio:bio -> wbio:bio -> unit

    val ssl_clear : ssl -> unit

    val ssl_set_session : ssl -> ssl_session -> unit
  end
end
