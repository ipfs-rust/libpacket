use crate::util::Endianness;
use proc_macro2::{Group, Span};
use quote::{quote, ToTokens};
use regex::Regex;
use std::iter::FromIterator;
use syn::{spanned::Spanned, Error};

#[derive(Debug, PartialEq, Eq)]
pub enum EndiannessSpecified {
    No,
    Yes,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Type {
    /// Any of the `u*` types from `libpacket_core::types::*`.
    Primitive(String, usize, Endianness),
    /// Any type of the form `Vec<T>`.
    Vector(Box<Type>),
    /// Any type which isn't a primitive or a vector.
    Misc(String),
}

#[derive(Clone, Debug)]
pub struct Field {
    pub name: String,
    pub span: Span,
    pub ty: Type,
    pub packet_length: Option<String>,
    pub struct_length: Option<String>,
    pub is_payload: bool,
    pub construct_with: Option<Vec<Type>>,
}

#[derive(Clone, Debug)]
pub struct Packet {
    pub base_name: String,
    pub fields: Vec<Field>,
}

impl Packet {
    pub fn packet_name(&self) -> String {
        format!("{}Packet", self.base_name)
    }
    pub fn packet_name_mut(&self) -> String {
        format!("Mutable{}Packet", self.base_name)
    }
}

pub fn packet(s: &syn::DataStruct, name: String) -> Result<Packet, Error> {
    let mut fields = Vec::new();
    let mut payload_span = None;
    let sfields = &s.fields;
    for (i, field) in sfields.iter().enumerate() {
        let field_name = match &field.ident {
            Some(name) => name.to_string(),
            None => {
                return Err(Error::new(
                    field.ty.span(),
                    "all fields in a packet must be named",
                ));
            }
        };
        let mut construct_with = Vec::new();
        let mut is_payload = false;
        let mut packet_length = None;
        let mut struct_length = None;
        for attr in &field.attrs {
            let node = attr.parse_meta()?;
            match node {
                syn::Meta::Path(p) => {
                    if let Some(ident) = p.get_ident() {
                        if ident == "payload" {
                            if payload_span.is_some() {
                                return Err(Error::new(
                                    p.span(),
                                    "packet may not have multiple payloads",
                                ));
                            }
                            is_payload = true;
                            payload_span = Some(field.span());
                        }
                    }
                }
                syn::Meta::NameValue(ref name_value) => {
                    if let Some(ident) = name_value.path.get_ident() {
                        if ident == "length" {
                            // get literal
                            if let syn::Lit::Str(ref s) = name_value.lit {
                                let field_names: Vec<String> = sfields
                                    .iter()
                                    .filter_map(|field| {
                                        field.ident.as_ref().map(|name| name.to_string()).and_then(
                                            |name| {
                                                if name == field_name {
                                                    None
                                                } else {
                                                    Some(name)
                                                }
                                            },
                                        )
                                    })
                                    .collect();
                                // Convert to tokens
                                let expr = s.parse::<syn::Expr>()?;
                                let tts = expr.to_token_stream();
                                let tt_tokens: Vec<_> = tts.into_iter().collect();
                                // Parse and replace fields
                                let tokens_packet = parse_length_expr(&tt_tokens, &field_names)?;
                                let parsed = quote! { (#(#tokens_packet)*) as usize };
                                packet_length = Some(parsed.to_string());
                            } else {
                                return Err(Error::new(
                                    name_value.lit.span(),
                                    "#[length] should be used as #[length = \
                                                \"field_name and/or arithmetic expression\"]",
                                ));
                            }
                        } else {
                            return Err(Error::new(
                                ident.span(),
                                &format!("Unknown meta/namevalue option '{}'", ident),
                            ));
                        }
                    }
                }
                syn::Meta::List(ref l) => {
                    if let Some(ident) = l.path.get_ident() {
                        if ident == "construct_with" {
                            if l.nested.is_empty() {
                                return Err(Error::new(
                                    l.path.span(),
                                    "#[construct_with] must have at least one argument",
                                ));
                            }

                            for item in &l.nested {
                                if let syn::NestedMeta::Meta(ref meta) = item {
                                    let ty_str = meta.to_token_stream().to_string();
                                    match parse_type(ty_str, false) {
                                        Ok(ty) => construct_with.push(ty),
                                        Err(e) => {
                                            return Err(Error::new(
                                                field.ty.span(),
                                                &format!("{}", e),
                                            ));
                                        }
                                    }
                                } else {
                                    // literal
                                    return Err(Error::new(
                                        l.nested.span(),
                                        "#[construct_with] should be of the form \
                                                #[construct_with(<types>)]",
                                    ));
                                }
                            }
                        } else {
                            return Err(Error::new(
                                ident.span(),
                                &format!("unknown attribute: {}", ident),
                            ));
                        }
                    } else {
                        return Err(Error::new(
                            l.path.span(),
                            "meta-list attribute has unexpected type (not an ident)",
                        ));
                    }
                }
            }
        }

        let ty = match parse_type(ty_to_string(&field.ty), true) {
            Ok(ty) => ty,
            Err(e) => {
                return Err(Error::new(field.ty.span(), &format!("{}", e)));
            }
        };

        match ty {
            Type::Vector(_) => {
                struct_length = Some(format!("_packet.{}.len()", field_name).to_owned());
                if i < sfields.len() - 1 && packet_length.is_none() {
                    return Err(Error::new(
                        field.ty.span(),
                        "variable length field must specify #[length], unless it is the \
                        last field of a packet",
                    ));
                }
            }
            Type::Misc(_) => {
                if construct_with.is_empty() {
                    return Err(Error::new(
                        field.ty.span(),
                        "non-primitive field types must specify #[construct_with]",
                    ));
                }
            }
            _ => {}
        }

        fields.push(Field {
            name: field_name,
            span: field.span(),
            ty,
            packet_length,
            struct_length,
            is_payload,
            construct_with: Some(construct_with),
        });
    }

    Ok(Packet {
        base_name: name,
        fields,
    })
}

/// Return the processed length expression for a packet.
fn parse_length_expr(
    tts: &[proc_macro2::TokenTree],
    field_names: &[String],
) -> Result<Vec<proc_macro2::TokenTree>, Error> {
    use proc_macro2::TokenTree;
    let error_msg = "Only field names, constants, integers, basic arithmetic expressions \
                     (+ - * / %) and parentheses are allowed in the \"length\" attribute";

    let mut tokens_packet = Vec::new();
    for tt_token in tts {
        match tt_token {
            TokenTree::Ident(name) => {
                if field_names.contains(&name.to_string()) {
                    let tts: syn::Expr = syn::parse_str(&format!("self.get_{}()", name))?;
                    let mut modified_packet_tokens: Vec<_> =
                        tts.to_token_stream().into_iter().collect();
                    tokens_packet.append(&mut modified_packet_tokens);
                } else {
                    tokens_packet.push(tt_token.clone());
                }
            }
            TokenTree::Punct(_) => {
                tokens_packet.push(tt_token.clone());
            }
            TokenTree::Literal(lit) => {
                // must be an integer
                if syn::parse_str::<syn::LitInt>(&lit.to_string()).is_err() {
                    return Err(Error::new(lit.span(), error_msg));
                }
                tokens_packet.push(tt_token.clone());
            }
            TokenTree::Group(ref group) => {
                let ts: Vec<_> = group.stream().into_iter().collect();
                let tts = parse_length_expr(&ts, field_names)?;
                let mut new_group = Group::new(
                    group.delimiter(),
                    proc_macro2::TokenStream::from_iter(tts.into_iter()),
                );
                new_group.set_span(group.span());
                let tt = TokenTree::Group(new_group);
                tokens_packet.push(tt);
            }
        };
    }

    Ok(tokens_packet)
}

fn parse_type(ty_str: String, endianness_important: bool) -> Result<Type, String> {
    if let Some((size, endianness, spec)) = parse_ty(&ty_str[..]) {
        if !endianness_important || size <= 8 || spec == EndiannessSpecified::Yes {
            Ok(Type::Primitive(ty_str, size, endianness))
        } else {
            Err("endianness must be specified for types of size >= 8".to_owned())
        }
    } else if ty_str.starts_with("Vec<") {
        let ty = parse_type(
            String::from(&ty_str[4..ty_str.len() - 1]),
            endianness_important,
        );
        match ty {
            Ok(ty) => Ok(Type::Vector(Box::new(ty))),
            Err(e) => Err(e),
        }
    } else if ty_str.starts_with("&") {
        Err(format!("invalid type: {}", ty_str))
    } else {
        Ok(Type::Misc(ty_str))
    }
}

/// Given a type in the form `u([0-9]+)(be|le)?`, return a tuple of it's size and endianness
///
/// If 1 <= size <= 8, Endianness will be Big.
pub fn parse_ty(ty: &str) -> Option<(usize, Endianness, EndiannessSpecified)> {
    let re = Regex::new(r"^u([0-9]+)(be|le|he)?$").unwrap();
    let iter = match re.captures_iter(ty).next() {
        Some(c) => c,
        None => return None,
    };
    if iter.len() == 3 || iter.len() == 2 {
        let size = iter.get(1).unwrap().as_str();
        let (endianness, has_end) = if let Some(e) = iter.get(2) {
            let e = e.as_str();
            if e == "be" {
                (Endianness::Big, EndiannessSpecified::Yes)
            } else if e == "he" {
                (Endianness::Host, EndiannessSpecified::Yes)
            } else {
                (Endianness::Little, EndiannessSpecified::Yes)
            }
        } else {
            (Endianness::Big, EndiannessSpecified::No)
        };

        if let Ok(sz) = size.parse() {
            Some((sz, endianness, has_end))
        } else {
            None
        }
    } else {
        None
    }
}

#[test]
fn test_parse_ty() {
    assert_eq!(
        parse_ty("u8"),
        Some((8, Endianness::Big, EndiannessSpecified::No))
    );
    assert_eq!(
        parse_ty("u21be"),
        Some((21, Endianness::Big, EndiannessSpecified::Yes))
    );
    assert_eq!(
        parse_ty("u21le"),
        Some((21, Endianness::Little, EndiannessSpecified::Yes))
    );
    assert_eq!(
        parse_ty("u21he"),
        Some((21, Endianness::Host, EndiannessSpecified::Yes))
    );
    assert_eq!(
        parse_ty("u9"),
        Some((9, Endianness::Big, EndiannessSpecified::No))
    );
    assert_eq!(
        parse_ty("u16"),
        Some((16, Endianness::Big, EndiannessSpecified::No))
    );
    assert_eq!(parse_ty("uable"), None);
    assert_eq!(parse_ty("u21re"), None);
    assert_eq!(parse_ty("i21be"), None);
}

fn ty_to_string(ty: &syn::Type) -> String {
    // XXX this inserts extra spaces (ex: "Vec < u8 >")
    let s = quote!(#ty).to_string();
    s.replace(" < ", "<").replace(" > ", ">").replace(" >", ">")
}
