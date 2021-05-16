// Copyright (c) 2015 Robert Clipsham <robert@octarineparrot.com>
// Copyright (c) 2021 Pierre Chifflier <chifflier@wzdftpd.net>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Implements the #[packet] decorator.

use crate::parse::{parse_ty, Packet, Type};
use crate::util::{operations, to_mutator, Endianness, GetOperation, SetOperation};
use quote::{format_ident, quote};
use syn::Error;

/// Lower and upper bounds of a payload.
/// Represented as strings since they may involve functions.
pub struct PayloadBounds {
    lower: proc_macro2::TokenStream,
    upper: proc_macro2::TokenStream,
}

pub fn packet_struct(packet: &Packet) -> proc_macro2::TokenStream {
    let name = format_ident!("{}", packet.packet_name());
    let name_mut = format_ident!("{}", packet.packet_name_mut());
    quote! {
        /// A structure enabling manipulation of on the wire packets
        #[derive(PartialEq)]
        pub struct #name<'p> {
            packet: libpacket_core::PacketData<'p>,
        }

        /// A structure enabling manipulation of on the wire packets
        #[derive(PartialEq)]
        pub struct #name_mut<'p> {
            packet: libpacket_core::MutPacketData<'p>,
        }
    }
}

pub fn packet_impls(
    packet: &Packet,
) -> Result<
    (
        proc_macro2::TokenStream,
        PayloadBounds,
        proc_macro2::TokenStream,
    ),
    Error,
> {
    let (p, bounds, size) = packet_impl(packet, false, packet.packet_name())?;
    let (p_mut, _, _) = packet_impl(packet, true, packet.packet_name())?;
    let tokens = quote! {
        #p

        #p_mut
    };
    Ok((tokens, bounds, size))
}

fn current_offset(bit_offset: usize, offset_fns: &[String]) -> proc_macro2::TokenStream {
    let base_offset = bit_offset / 8;
    let offset = offset_fns
        .iter()
        .fold(base_offset.to_string(), |a, b| a + " + " + &b[..]);
    let offset = syn::parse_str::<syn::Expr>(&offset).unwrap();
    quote!(#offset)
}

fn packet_impl(
    packet: &Packet,
    mutable: bool,
    name: String,
) -> Result<
    (
        proc_macro2::TokenStream,
        PayloadBounds,
        proc_macro2::TokenStream,
    ),
    Error,
> {
    let mut bit_offset = 0;
    let mut offset_fns_packet = Vec::new();
    let mut offset_fns_struct = Vec::new();
    let mut accessors = vec![];
    let mut mutators = vec![];
    let mut populate = vec![];
    let mut payload_bounds = PayloadBounds {
        lower: quote!(0),
        upper: quote!(0),
    };
    for field in &packet.fields {
        let field_name = format_ident!("{}", field.name);
        let get_field_name = format_ident!("get_{}", field.name);
        let set_field_name = format_ident!("set_{}", field.name);
        let mut co = current_offset(bit_offset, &offset_fns_packet[..]);
        let packet_length = if let Some(packet_length) = field.packet_length.as_ref() {
            let packet_length = syn::parse_str::<syn::Expr>(&packet_length)?;
            quote!(#packet_length)
        } else {
            quote!(0)
        };
        if field.is_payload {
            let upper_bound = if field.packet_length.is_some() {
                quote!(#co + #packet_length)
            } else {
                quote!(0)
            };
            payload_bounds = PayloadBounds {
                lower: co.clone(),
                upper: upper_bound,
            };
        }
        match field.ty {
            Type::Primitive(ref ty, size, endianness) => {
                let ops = operations(bit_offset % 8, size, endianness).unwrap();
                mutators.push(gen_mutator(&field.name, ty, &co, &to_mutator(&ops), None));
                accessors.push(gen_accessor(&field.name, ty, &co, &ops, None));
                bit_offset += size;
            }
            Type::Vector(ref inner_ty) => {
                if !field.is_payload {
                    let get_field_name_raw = format_ident!("get_{}_raw", field.name);
                    let get_field_name_raw_mut = format_ident!("get_{}_raw_mut", field.name);
                    accessors.push(quote! {
                        /// Get the raw &[u8] value of the {name} field, without copying
                        #[inline]
                        #[allow(trivial_numeric_casts)]
                        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                        pub fn #get_field_name_raw(&self) -> &[u8] {
                            use std::cmp::min;
                            let current_offset = #co;
                            let end = min(current_offset + #packet_length, self.packet.len());
                            &self.packet[current_offset..end]
                        }
                    });
                    mutators.push(quote! {
                        /// Get the raw &mut [u8] value of the {name} field, without copying
                        #[inline]
                        #[allow(trivial_numeric_casts)]
                        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                        pub fn #get_field_name_raw_mut(&mut self) -> &mut [u8] {
                            use std::cmp::min;
                            let current_offset = #co;
                            let end = min(current_offset + #packet_length, self.packet.len());
                            &mut self.packet[current_offset..end]
                        }
                    });
                }
                match **inner_ty {
                    Type::Primitive(ref inner_ty_str, size, _endianness) => {
                        let inner_ty: syn::Type = syn::parse_str(inner_ty_str)?;
                        if size % 8 != 0 {
                            return Err(Error::new(
                                field.span,
                                "unimplemented variable length field",
                            ));
                        }
                        let get_name = format_ident!("get_{}", field.name);
                        let set_name = format_ident!("set_{}", field.name);
                        let ops = operations(0, size, Endianness::Big).unwrap();
                        let size = size / 8;
                        let access_ops = gen_get_ops("packet", inner_ty_str, &ops);
                        accessors.push(quote! {
                            /// Get the value of the {name} field (copies contents)
                            #[inline]
                            #[allow(trivial_numeric_casts, unused_parens, unused_braces)]
                            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                            pub fn #get_name(&self) -> Vec<#inner_ty> {
                                use std::cmp::min;
                                let current_offset = #co;
                                let pkt_len = self.packet.len();
                                let end = min(current_offset + #packet_length, pkt_len);

                                let packet = &self.packet[current_offset..end];
                                let mut vec: Vec<#inner_ty> = Vec::with_capacity(packet.len());
                                let mut co = 0;
                                for _ in 0..vec.capacity() {
                                    vec.push(#access_ops);
                                    co += #size;
                                }
                                vec
                            }
                        });
                        let check_len = if field.packet_length.is_some() {
                            quote! {
                                let len = #packet_length;
                                assert!(vals.len() <= len);
                            }
                        } else {
                            quote!()
                        };
                        let copy_vals = if inner_ty_str == "u8" {
                            // Efficient copy_from_slice (memcpy)
                            quote! {
                                self.packet[current_offset..current_offset + vals.len()]
                                    .copy_from_slice(vals);
                            }
                        } else {
                            // e.g. Vec<u16> -> Vec<u8>
                            let sop = gen_set_ops(&to_mutator(&ops));
                            quote! {
                                let mut co = current_offset;
                                for i in 0..vals.len() {
                                    let val = vals[i];
                                    #sop
                                    co += #size;
                                }
                            }
                        };
                        mutators.push(quote! {
                            /// Set the value of the {name} field (copies contents)
                            #[inline]
                            #[allow(trivial_numeric_casts)]
                            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                            pub fn #set_name(&mut self, vals: &[#inner_ty]) {
                                let current_offset = #co;
                                #check_len
                                #copy_vals
                           }
                        });
                    }
                    Type::Vector(_) => {
                        return Err(Error::new(
                            field.span,
                            "variable length fields may not contain vectors",
                        ));
                    }
                    Type::Misc(ref inner_ty_str) => {
                        let get_name = format_ident!("get_{}", field.name);
                        let set_name = format_ident!("set_{}", field.name);
                        let get_name_iter = format_ident!("get_{}_iter", field.name);
                        let inner_ty_iterable = format_ident!("{}Iterable", inner_ty_str);
                        let inner_ty: syn::Type = syn::parse_str(inner_ty_str)?;
                        let inner_ty_packet_mut = format_ident!("Mutable{}Packet", inner_ty_str);
                        accessors.push(quote! {
                            /// Get the value of the {name} field (copies contents)
                            #[inline]
                            #[allow(trivial_numeric_casts)]
                            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                            pub fn #get_name(&self) -> Vec<#inner_ty> {
                                self.get_name_iter().collect::<Vec<_>>()
                            }

                            /// Get the value of the {name} field as iterator
                            #[inline]
                            #[allow(trivial_numeric_casts)]
                            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                            pub fn #get_name_iter(&self) -> #inner_ty_iterable {
                                use std::cmp::min;
                                let current_offset = #co;
                                let end = min(current_offset + #packet_length, self.packet.len());
                                #inner_ty_iterable {
                                    buf: &self.packet[current_offset..end]
                                }
                            }
                        });
                        mutators.push(quote! {
                            /// Set the value of the {name} field (copies contents)
                            #[inline]
                            #[allow(trivial_numeric_casts)]
                            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                            pub fn #set_name(&mut self, vals: &[#inner_ty]) {
                                use libpacket_core::PacketSize;
                                let mut current_offset = #co;
                                let end = current_offset + #packet_length;
                                for val in vals.into_iter() {
                                    let mut packet = #inner_ty_packet_mut::new(&mut self.packet[current_offset..]).unwrap()
                                    packet.populate(val);
                                    current_offset += packet.packet_size();
                                    assert!(current_offset <= end);
                                }
                            }
                        });
                    }
                }
            }
            Type::Misc(ref ty) => {
                let mut inner_accessors = vec![];
                let mut inner_mutators = vec![];
                let mut get_args = vec![];
                let mut set_args = vec![];
                let construct_with = field.construct_with.as_ref().expect("construct_with");
                for (i, arg) in construct_with.iter().enumerate() {
                    if let Type::Primitive(ref ty_str, size, endianness) = *arg {
                        let ops = operations(bit_offset % 8, size, endianness).unwrap();
                        let arg_name = format!("arg{}", i);
                        let get_arg = format_ident!("get_arg{}", i);
                        let set_arg = format_ident!("set_arg{}", i);
                        inner_accessors.push(gen_accessor(
                            &arg_name,
                            &ty_str,
                            &co,
                            &ops,
                            Some(&name),
                        ));
                        inner_mutators.push(gen_mutator(
                            &arg_name,
                            &ty_str,
                            &co,
                            &to_mutator(&ops),
                            Some(&name),
                        ));
                        get_args.push(quote!(#get_arg(&self)));
                        set_args.push(quote!(#set_arg(self, vals.#i)));
                        bit_offset += size;
                        // Current offset needs to be recalculated for each arg
                        co = current_offset(bit_offset, &offset_fns_packet);
                    } else {
                        return Err(Error::new(
                            field.span,
                            "arguments to #[construct_with] must be primitives",
                        ));
                    }
                }
                mutators.push(quote! {
                    /// Set the value of the {name} field.
                    #[inline]
                    #[allow(trivial_numeric_casts)]
                    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                    pub fn #set_field_name(&mut self, val: #ty) {
                        use libpacket_core::PrimitiveValues;
                        #(#inner_mutators)*

                        let vals = val.to_primitive_values();

                        #(#set_args,)*
                    }
                });
                let get_args = &get_args[..get_args.len() - 2];
                accessors.push(quote! {
                    /// Get the value of the {name} field
                    #[inline]
                    #[allow(trivial_numeric_casts)]
                    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                    pub fn #get_field_name(&self) -> #ty {
                        #(#inner_accessors)*
                        #ty::new(#(#get_args,)*)
                    }
                });
            }
        }
        if let Some(packet_length) = field.packet_length.clone() {
            offset_fns_packet.push(packet_length);
        }
        if let Some(struct_length) = field.struct_length.clone() {
            offset_fns_struct.push(struct_length);
        }
        if let Type::Vector(_) = &field.ty {
            populate.push(quote!(self.#set_field_name(&packet.#field_name);));
        } else {
            populate.push(quote!(self.#set_field_name(packet.#field_name);));
        }
    }

    let populate = if mutable {
        let base_name = format_ident!("{}", &packet.base_name);
        quote! {
            /// Populates a {name}Packet using a {name} structure
            #[inline]
            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
            pub fn populate(&mut self, packet: &#base_name) {
                 #(#populate)*
            }
        }
    } else {
        quote!()
    };

    let name = if mutable {
        format_ident!("{}", packet.packet_name_mut())
    } else {
        format_ident!("{}", packet.packet_name())
    };
    let base_name = format_ident!("{}", &packet.base_name);
    let struct_size = current_offset(bit_offset, &offset_fns_struct[..]);
    let byte_size = if bit_offset % 8 == 0 {
        bit_offset / 8
    } else {
        (bit_offset / 8) + 1
    };
    let imm_name = format_ident!("{}", packet.packet_name());
    let mut_ = if mutable { quote!(mut) } else { quote!() };
    let packet_data = if mutable {
        format_ident!("MutPacketData")
    } else {
        format_ident!("PacketData")
    };
    let mutators = if mutable { mutators } else { vec![] };

    let tokens = quote! {
        impl<'a> #name<'a> {
            /// Constructs a new #name. If the provided buffer is less than the minimum required
            /// packet size, this will return None.
            #[inline]
            pub fn new<'p>(packet: &'p #mut_ [u8]) -> Option<#name<'p>> {
                if packet.len() >= #name::minimum_packet_size() {
                    use libpacket_core::#packet_data;
                    Some(#name { packet: #packet_data::Borrowed(packet) })
                } else {
                    None
                }
            }

            /// Constructs a new #name. If the provided buffer is less than the minimum required
            /// packet size, this will return None. With this constructor the #name will
            /// own its own data and the underlying buffer will be dropped when the #name is.
            pub fn owned(packet: Vec<u8>) -> Option<#name<'static>> {
                if packet.len() >= #name::minimum_packet_size() {
                    use libpacket_core::#packet_data;
                    Some(#name { packet: #packet_data::Owned(packet) })
                } else {
                    None
                }
            }

            /// Maps from a #name to a #imm_name
            #[inline]
            pub fn to_immutable<'p>(&'p self) -> #imm_name<'p> {
                use libpacket_core::PacketData;
                #imm_name { packet: PacketData::Borrowed(self.packet.as_slice()) }
            }

            /// Maps from a #name to a #imm_name while consuming the source
            #[inline]
            pub fn consume_to_immutable(self) -> #imm_name<'a> {
                #imm_name { packet: self.packet.to_immutable() }
            }

            /// The minimum size (in bytes) a packet of this type can be. It's based on the total size
            /// of the fixed-size fields.
            #[inline]
            pub const fn minimum_packet_size() -> usize {
                #byte_size
            }

            /// The size (in bytes) of a #base_name instance when converted into
            /// a byte-array
            #[inline]
            pub fn packet_size(_packet: &#base_name) -> usize {
                // If there are no variable length fields defined, then `_packet` is not used, hence
                // the leading underscore
                #struct_size
            }

            #populate

            #(#accessors)*

            #(#mutators)*
        }
    };

    Ok((
        tokens,
        payload_bounds,
        current_offset(bit_offset, &offset_fns_packet[..]),
    ))
}

/// Given the name of a field, and a set of operations required to get the value of that field,
/// return the Rust code required to get the field.
fn gen_accessor(
    name: &str,
    ty_str: &str,
    offset: &proc_macro2::TokenStream,
    operations: &[GetOperation],
    inner: Option<&str>,
) -> proc_macro2::TokenStream {
    let get_name = format_ident!("get_{}", name);
    let operations = gen_get_ops("self.packet", ty_str, operations);
    let ty: syn::Type = syn::parse_str(ty_str).unwrap();

    if let Some(struct_name) = inner {
        quote! {
            #[inline(always)]
            #[allow(trivial_numeric_casts, unused_parens)]
            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
            fn #get_name(self: &#struct_name) -> #ty {
                let co = #offset;
                #operations
            }
        }
    } else {
        let comment = if let Some((_, endianness, _)) = parse_ty(ty_str) {
            format!(
                "Get the {name} field. This field is always stored {endian} \
                within the struct, but this accessor returns host order.",
                name = name,
                endian = endianness,
            )
        } else {
            format!("Get the {name} field.", name = name)
        };
        quote! {
            #[doc = #comment]
            #[inline]
            #[allow(trivial_numeric_casts, unused_parens)]
            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
            pub fn #get_name(&self) -> #ty {
                let co = #offset;
                #operations
            }
        }
    }
}

/// Given the name of a field, and a set of operations required to set that field, return
/// the Rust code required to set the field
fn gen_mutator(
    name: &str,
    ty_str: &str,
    offset: &proc_macro2::TokenStream,
    operations: &[SetOperation],
    inner: Option<&str>,
) -> proc_macro2::TokenStream {
    let set_name = format_ident!("set_{}", name);
    let operations = gen_set_ops(operations);
    let ty: syn::Type = syn::parse_str(ty_str).unwrap();

    if let Some(struct_name) = inner {
        quote! {
            #[inline]
            #[allow(trivial_numeric_casts)]
            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
            fn #set_name(self: &mut #struct_name, val: #ty) {
                let co = #offset;
                #operations
            }
        }
    } else {
        let comment = if let Some((_, endianness, _)) = parse_ty(ty_str) {
            format!(
                "Set the {name} field. This field is always stored {endian} \
                within the struct, but this mutator wants host order.",
                name = name,
                endian = endianness,
            )
        } else {
            format!("Set the {name} field.", name = name)
        };
        quote! {
            #[doc = #comment]
            #[inline]
            #[allow(trivial_numeric_casts)]
            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
            pub fn #set_name(&mut self, val: #ty) {
                let co = #offset;
                #operations
            }
        }
    }
}

pub fn packet_size_impls(
    packet: &Packet,
    size: &proc_macro2::TokenStream,
) -> Result<proc_macro2::TokenStream, Error> {
    let name = format_ident!("{}", packet.packet_name());
    let name_mut = format_ident!("{}", packet.packet_name_mut());
    Ok(quote! {
        impl<'a> libpacket_core::PacketSize for #name<'a> {
            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
            fn packet_size(&self) -> usize {
                #size
            }
        }

        impl<'a> libpacket_core::PacketSize for #name_mut<'a> {
            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
            fn packet_size(&self) -> usize {
                #size
            }
        }
    })
}

pub fn packet_trait_impls(
    packet: &Packet,
    payload_bounds: &PayloadBounds,
) -> Result<proc_macro2::TokenStream, Error> {
    let a = impl_packet_trait_for(payload_bounds, packet.packet_name(), false)?;
    let b = impl_packet_trait_for(payload_bounds, packet.packet_name_mut(), false)?;
    let c = impl_packet_trait_for(payload_bounds, packet.packet_name_mut(), true)?;
    Ok(quote! {
        #a

        #b

        #c
    })
}

fn impl_packet_trait_for(
    payload_bounds: &PayloadBounds,
    name: String,
    mutable: bool,
) -> Result<proc_macro2::TokenStream, Error> {
    let name = format_ident!("{}", name);
    let lower = &payload_bounds.lower;
    let upper = &payload_bounds.upper;
    let mut_ = if mutable { quote!(mut) } else { quote!() };
    let packet = if mutable {
        quote!(packet_mut)
    } else {
        quote!(packet)
    };
    let payload = if mutable {
        quote!(payload_mut)
    } else {
        quote!(payload)
    };
    let trait_name = if mutable {
        quote!(MutablePacket)
    } else {
        quote!(Packet)
    };
    Ok(quote! {
        impl<'a> libpacket_core::#trait_name for #name<'a> {
            #[inline]
            fn #packet<'p>(&'p #mut_ self) -> &'p #mut_ [u8] {
                &#mut_ self.packet[..]
            }

            #[inline]
            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
            fn #payload<'p>(&'p #mut_ self) -> &'p #mut_ [u8] {
                let start = #lower;
                let end = std::cmp::min(#upper, self.packet.len());
                if self.packet.len() <= start {
                    return &#mut_ [];
                }
                &#mut_ self.packet[start..end]
            }
        }
    })
}

pub fn iterables(packet: &Packet) -> Result<proc_macro2::TokenStream, Error> {
    let iterator = format_ident!("{}Iterable", &packet.base_name);
    let packet_name = format_ident!("{}", packet.packet_name());
    Ok(quote! {
        /// Used to iterate over a slice of `{name}Packet`s
        pub struct #iterator<'a> {
            buf: &'a [u8],
        }

        impl<'a> Iterator for #iterator<'a> {
            type Item = #packet_name<'a>;

            fn next(&mut self) -> Option<#packet_name<'a>> {
                use libpacket_core::PacketSize;
                use std::cmp::min;
                if self.buf.len() > 0 {
                    if let Some(ret) = #packet_name::new(self.buf) {
                        let start = min(ret.packet_size(), self.buf.len());
                        self.buf = &self.buf[start..];
                        return Some(ret);
                    }
                }
                None
            }

            fn size_hint(&self) -> (usize, Option<usize>) {
                (0, None)
            }
        }
    })
}

pub fn converters(packet: &Packet) -> Result<proc_macro2::TokenStream, Error> {
    let name = format_ident!("{}", packet.base_name);
    let packet_name = format_ident!("{}", packet.packet_name());
    let packet_name_mut = format_ident!("{}", packet.packet_name_mut());
    let mut get_fields = vec![];
    for field in &packet.fields {
        let field_name = format_ident!("{}", &field.name);
        let get_field_name = format_ident!("get_{}", &field.name);
        if let Type::Vector(_) = &field.ty {
            get_fields.push(quote!(#field_name: self.#get_field_name().to_vec()));
        } else {
            get_fields.push(quote!(#field_name: self.#get_field_name()));
        }
    }
    Ok(quote! {
        impl<'p> libpacket_core::FromPacket for #packet_name<'p> {
            type T = #name;
            #[inline]
            fn from_packet(&self) -> #name {
                use libpacket_core::Packet;
                #name {
                    #(#get_fields,)*
                }
            }
        }

        impl<'p> libpacket_core::FromPacket for #packet_name_mut<'p> {
            type T = #name;
            #[inline]
            fn from_packet(&self) -> #name {
                use libpacket_core::Packet;
                #name {
                    #(#get_fields,)*
                }
            }
        }
    })
}

pub fn debug_impls(packet: &Packet) -> Result<proc_macro2::TokenStream, Error> {
    let mut field_fmt_str = String::new();
    let mut get_fields = vec![];

    for field in &packet.fields {
        if !field.is_payload {
            let get_field_name = format_ident!("get_{}", field.name);
            field_fmt_str = format!("{}{} : {{:?}}, ", field_fmt_str, field.name);
            get_fields.push(quote!(self.#get_field_name()));
        }
    }

    let packet_name = format_ident!("{}", packet.packet_name());
    let packet_fmt_str = format!("{} {{{{ {} }}}}", packet.packet_name(), field_fmt_str);
    let packet_name_mut = format_ident!("{}", packet.packet_name_mut());
    let packet_mut_fmt_str = format!("{} {{{{ {} }}}}", packet.packet_name_mut(), field_fmt_str);
    Ok(quote! {
        impl<'p> std::fmt::Debug for #packet_name<'p> {
            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
            fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(fmt, #packet_fmt_str, #(#get_fields,)*)
            }
        }

        impl<'p> std::fmt::Debug for #packet_name_mut<'p> {
            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
            fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(fmt, #packet_mut_fmt_str, #(#get_fields,)*)
            }
        }
    })
}

fn gen_set_ops(operations: &[SetOperation]) -> proc_macro2::TokenStream {
    let mut op_strings = String::new();
    for (idx, sop) in operations.iter().enumerate() {
        let pkt_replace = format!("self.packet[co + {}]", idx);
        let val_replace = "val";
        let sop = sop
            .to_string()
            .replace("{packet}", &pkt_replace[..])
            .replace("{val}", val_replace);
        op_strings = op_strings + &sop[..] + ";\n";
    }
    let stmt = syn::parse_str::<syn::Expr>(&format!("{{{}}}", op_strings)).expect("gen_set_ops");
    quote!(#stmt)
}

/// Used to turn something like a u16be into
/// "let b0 = ((self.packet[co + 0] as u16be) << 8) as u16be;
///  let b1 = ((self.packet[co + 1] as u16be) as u16be;
///  b0 | b1"
fn gen_get_ops(name: &str, ty: &str, operations: &[GetOperation]) -> proc_macro2::TokenStream {
    fn build_return(max: usize) -> String {
        let mut ret = "".to_owned();
        for i in 0..max {
            ret = ret + &format!("b{} | ", i)[..];
        }
        let new_len = ret.len() - 3;
        ret.truncate(new_len);

        ret
    }

    let op_strings = if operations.len() == 1 {
        let replacement_str = format!("({}[co] as {})", name, ty);
        operations
            .first()
            .unwrap()
            .to_string()
            .replace("{}", &replacement_str[..])
    } else {
        let mut op_strings = "".to_owned();
        for (idx, operation) in operations.iter().enumerate() {
            let replacement_str = format!("({}[co + {}] as {})", name, idx, ty);
            let operation = operation.to_string().replace("{}", &replacement_str[..]);
            op_strings = op_strings + &format!("let b{} = ({}) as {};\n", idx, operation, ty)[..];
        }
        op_strings = op_strings + &format!("\n{}\n", build_return(operations.len()))[..];

        op_strings
    };
    let stmt = syn::parse_str::<syn::Expr>(&format!("{{{}}}", op_strings)).expect("gen_get_ops");
    quote!(#stmt)
}

#[test]
fn test_gen_get_ops() {
    {
        let ops = operations(0, 24, Endianness::Big).unwrap();
        let result = gen_get_ops("test", "u24be", &ops);
        let expected = quote! {{
            let b0 = ((test[co + 0] as u24be) << 16) as u24be;
            let b1 = ((test[co + 1] as u24be) << 8) as u24be;
            let b2 = ((test[co + 2] as u24be)) as u24be;
            b0 | b1 | b2
        }};

        assert_eq!(result.to_string(), expected.to_string());
    }

    {
        let ops = operations(0, 16, Endianness::Big).unwrap();
        let result = gen_get_ops("test", "u16be", &ops);
        let expected = quote! {{
            let b0 = ((test[co + 0] as u16be) << 8) as u16be;
            let b1 = ((test[co + 1] as u16be)) as u16be;
            b0 | b1
        }};
        assert_eq!(result.to_string(), expected.to_string());
    }

    {
        let ops = operations(0, 8, Endianness::Big).unwrap();
        let result = gen_get_ops("test", "u8", &ops);
        let expected = quote!({ (test[co] as u8) });
        assert_eq!(result.to_string(), expected.to_string());
    }
}
