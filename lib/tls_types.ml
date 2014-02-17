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

module type OPENSSL_BASIC = sig

  type ssl_method
  type ssl_ctx
  type ssl
  type ssl_session

  type verify_callback = int -> unit ptr -> int

  val verify_callback : verify_callback typ

  val sslv23_server_method : ssl_method
  val sslv3_server_method  : ssl_method
  val tlsv1_server_method  : ssl_method
  val sslv23_client_method : ssl_method
  val sslv3_client_method  : ssl_method
  val tlsv1_client_method  : ssl_method

  val ssl_library_init : unit -> int
  val ssl_load_error_strings : unit -> unit
  val ssl_ctx_new : ssl_method -> ssl_ctx
  val ssl_ctx_free : ssl_ctx -> unit
  val ssl_ctx_use_certificate_file : ssl_ctx -> string -> int -> int
  val ssl_ctx_use_privatekey_file : ssl_ctx -> string -> int -> int
  val ssl_ctx_use_certificate_asn1 : ssl_ctx -> int -> Unsigned.uint8 ptr -> int
  val ssl_ctx_set_session_id_context : ssl_ctx -> string -> int -> int
  val ssl_ctx_set_default_verify_paths : ssl_ctx -> int
  val ssl_ctx_use_certificate_chain_file : ssl_ctx -> string -> int
  val ssl_ctx_ctrl : ssl_ctx -> int -> Signed.long -> unit ptr -> Signed.long
  val ssl_ctx_set_verify : ssl_ctx -> int -> (int -> unit ptr -> int) -> unit
  val ssl_ctx_set_verify_depth : ssl_ctx -> int -> unit
  val ssl_ctx_load_verify_locations : ssl_ctx -> string -> string -> int
  val ssl_load_client_ca_file : string -> unit ptr
  val ssl_ctx_set_client_ca_list : ssl_ctx -> unit ptr -> unit
  val ssl_ctx_set_default_passwd_cb : ssl_ctx -> unit ptr -> unit
  val ssl_ctx_set_default_passwd_cd_userdata : ssl_ctx -> unit ptr -> unit
  val ssl_ctx_check_private_key : ssl_ctx -> int
  val ssl_ctx_set_cipher_list : ssl_ctx -> string -> int
  val ssl_ctx_set_options : ssl_ctx -> int -> unit
  val ssl_new : ssl_ctx -> ssl
  val ssl_set_fd : ssl -> Unix.file_descr -> int
  val ssl_accept : ssl -> int
  val ssl_connect : ssl -> int
  val ssl_free : ssl -> unit
  val ssl_read : ssl -> unit ptr -> int -> int
  val ssl_write : ssl -> unit ptr -> int -> int
  val ssl_shutdown : ssl -> int
  val ssl_peek : ssl -> unit ptr -> int -> int
  val ssl_set_bio : ssl -> unit ptr -> unit ptr -> unit
  val ssl_get_verify_result : ssl -> Signed.long
  val ssl_state : ssl -> int
  val ssl_get_peer_certificate : ssl -> unit ptr
  val ssl_clear : ssl -> int
  val ssl_get_error : ssl -> int -> int
  val ssl_get1_session : ssl -> ssl_session
  val ssl_set_session : ssl -> ssl_session -> int
  val ssl_session_free : ssl_session -> unit

end

module Bindings(F : sig val funptr : ('a -> 'b) fn -> ('a -> 'b) typ end) =
struct
  module Openssl_basic = struct
    type verify_callback = int -> unit ptr -> int

    let verify_callback = F.funptr (int @-> ptr void @-> returning int)
  end
end
