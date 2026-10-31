use proc_macro::TokenStream;
use quote::quote;
use syn::spanned::Spanned;
use syn::{Attribute, Data, DeriveInput, Fields, Ident, Meta, Result, Variant, parse_macro_input};

#[proc_macro_derive(MessageBusinessRef, attributes(business_ref))]
pub fn derive_message_business_ref(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand_message_business_ref(input) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.into_compile_error().into(),
    }
}

fn expand_message_business_ref(input: DeriveInput) -> Result<proc_macro2::TokenStream> {
    let enum_name = input.ident;
    let Data::Enum(data) = input.data else {
        return Err(syn::Error::new(
            enum_name.span(),
            "MessageBusinessRef can only be derived for enums",
        ));
    };

    let match_arms = data.variants.iter().map(expand_variant).collect::<Result<Vec<_>>>()?;

    Ok(quote! {
        impl HasBusinessRef for #enum_name {
            fn business_ref(&self) -> BusinessRef {
                match self {
                    #(#match_arms),*
                }
            }
        }
    })
}

fn expand_variant(variant: &Variant) -> Result<proc_macro2::TokenStream> {
    let scope = business_ref_scope(variant)?;
    let variant_name = &variant.ident;

    match scope.as_str() {
        "graph" => {
            let binding = tuple_payload_binding(variant)?;
            Ok(quote! {
                Self::#variant_name(#binding) => BusinessRef::Graph {
                    instance_id: #binding.instance_id,
                    graph_id: #binding.graph_id,
                }
            })
        }
        "instance" => {
            let binding = tuple_payload_binding(variant)?;
            Ok(quote! {
                Self::#variant_name(#binding) => BusinessRef::Instance {
                    instance_id: #binding.instance_id,
                }
            })
        }
        "unscoped" => match &variant.fields {
            Fields::Unit => Ok(quote! {
                Self::#variant_name => BusinessRef::Unscoped
            }),
            Fields::Unnamed(_) => Ok(quote! {
                Self::#variant_name(..) => BusinessRef::Unscoped
            }),
            Fields::Named(_) => Ok(quote! {
                Self::#variant_name { .. } => BusinessRef::Unscoped
            }),
        },
        _ => unreachable!("business_ref_scope validates accepted values"),
    }
}

fn tuple_payload_binding(variant: &Variant) -> Result<Ident> {
    match &variant.fields {
        Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
            Ok(Ident::new("message", variant.span()))
        }
        _ => Err(syn::Error::new(
            variant.span(),
            "graph and instance business references require exactly one payload field",
        )),
    }
}

fn business_ref_scope(variant: &Variant) -> Result<String> {
    let mut matching = variant
        .attrs
        .iter()
        .filter(|attribute: &&Attribute| attribute.path().is_ident("business_ref"));
    let Some(attribute) = matching.next() else {
        // Point at the offending variant rather than the derive site, so the
        // compiler error names the variant that lacks an attribute.
        return Err(syn::Error::new(
            variant.ident.span(),
            "each message variant must declare #[business_ref(graph)], #[business_ref(instance)], or #[business_ref(unscoped)]",
        ));
    };
    if matching.next().is_some() {
        return Err(syn::Error::new(attribute.span(), "duplicate business_ref attribute"));
    }

    let Meta::List(list) = &attribute.meta else {
        return Err(syn::Error::new(
            attribute.span(),
            "business_ref must be written as #[business_ref(graph)], #[business_ref(instance)], or #[business_ref(unscoped)]",
        ));
    };
    let scope: Ident = list.parse_args()?;
    let scope = scope.to_string();
    if matches!(scope.as_str(), "graph" | "instance" | "unscoped") {
        Ok(scope)
    } else {
        Err(syn::Error::new(attribute.span(), "business_ref must be graph, instance, or unscoped"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    fn expand_error(input: DeriveInput) -> String {
        expand_message_business_ref(input).unwrap_err().to_string()
    }

    #[test]
    fn rejects_non_enum_input() {
        let input = parse_quote! {
            struct Message;
        };

        assert_eq!(expand_error(input), "MessageBusinessRef can only be derived for enums");
    }

    #[test]
    fn requires_a_business_ref_scope_for_every_variant() {
        let input = parse_quote! {
            enum Message {
                Missing(Payload),
            }
        };

        assert_eq!(
            expand_error(input),
            "each message variant must declare #[business_ref(graph)], #[business_ref(instance)], or #[business_ref(unscoped)]"
        );
    }

    #[test]
    fn rejects_invalid_or_duplicate_scopes() {
        let invalid = parse_quote! {
            enum Message {
                #[business_ref(other)]
                Invalid(Payload),
            }
        };
        assert_eq!(expand_error(invalid), "business_ref must be graph, instance, or unscoped");

        let duplicate = parse_quote! {
            enum Message {
                #[business_ref(graph)]
                #[business_ref(instance)]
                Duplicate(Payload),
            }
        };
        assert_eq!(expand_error(duplicate), "duplicate business_ref attribute");
    }

    #[test]
    fn graph_and_instance_scopes_require_one_tuple_payload() {
        let named = parse_quote! {
            enum Message {
                #[business_ref(graph)]
                Graph { payload: Payload },
            }
        };
        assert_eq!(
            expand_error(named),
            "graph and instance business references require exactly one payload field"
        );

        let multiple = parse_quote! {
            enum Message {
                #[business_ref(instance)]
                Instance(Payload, Payload),
            }
        };
        assert_eq!(
            expand_error(multiple),
            "graph and instance business references require exactly one payload field"
        );
    }

    #[test]
    fn accepts_all_unscoped_variant_shapes() {
        let input = parse_quote! {
            enum Message {
                #[business_ref(unscoped)]
                Unit,
                #[business_ref(unscoped)]
                Tuple(u8, u16),
                #[business_ref(unscoped)]
                Named { value: u8 },
            }
        };

        assert!(expand_message_business_ref(input).is_ok());
    }
}
