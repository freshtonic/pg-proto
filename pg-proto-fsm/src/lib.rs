//! Protocol grammar to typestate, runtime FSM, and railroad-diagram generation.

use std::collections::{BTreeMap, BTreeSet};

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use railroad::{Choice, Diagram, End, Node, NonTerminal, Sequence, Start, Stylesheet, Terminal};
use syn::{
    Ident, Result, Token, Visibility, braced,
    parse::{Parse, ParseStream},
    parse_macro_input,
};

mod keyword {
    syn::custom_keyword!(initial);
}

struct Protocol {
    visibility: Visibility,
    module: Ident,
    initial: Ident,
    states: Vec<State>,
}

struct State {
    name: Ident,
    choice: ChoiceKind,
    transitions: Vec<Transition>,
}

#[derive(Clone, Copy)]
enum ChoiceKind {
    Internal,
    External,
}

struct Transition {
    event: Ident,
    method: Ident,
    target: Ident,
}

impl Parse for Protocol {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let visibility = input.parse()?;
        input.parse::<Token![mod]>()?;
        let module = input.parse()?;
        let content;
        braced!(content in input);
        content.parse::<keyword::initial>()?;
        let initial = content.parse()?;
        content.parse::<Token![;]>()?;
        let mut states = Vec::new();
        while !content.is_empty() {
            states.push(content.parse()?);
        }
        Ok(Self {
            visibility,
            module,
            initial,
            states,
        })
    }
}

impl Parse for State {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let name = input.parse()?;
        let choice_name: Ident = input.parse()?;
        let choice = match choice_name.to_string().as_str() {
            "internal" => ChoiceKind::Internal,
            "external" => ChoiceKind::External,
            _ => {
                return Err(syn::Error::new(
                    choice_name.span(),
                    "expected `internal` or `external` choice",
                ));
            }
        };
        let content;
        braced!(content in input);
        let transitions = content
            .parse_terminated(Transition::parse, Token![,])?
            .into_iter()
            .collect();
        Ok(Self {
            name,
            choice,
            transitions,
        })
    }
}

impl Parse for Transition {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let event = input.parse()?;
        let method_content;
        syn::parenthesized!(method_content in input);
        let method = method_content.parse()?;
        input.parse::<Token![=>]>()?;
        let target = input.parse()?;
        Ok(Self {
            event,
            method,
            target,
        })
    }
}

/// Generates typestate witnesses, a runtime FSM, and a railroad SVG from one grammar.
///
/// The grammar uses `Event(method) => NextState` transitions grouped by source state.
#[proc_macro]
pub fn protocol(input: TokenStream) -> TokenStream {
    let protocol = parse_macro_input!(input as Protocol);
    expand(protocol)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

#[allow(clippy::too_many_lines)]
fn expand(protocol: Protocol) -> Result<proc_macro2::TokenStream> {
    validate(&protocol)?;
    let Protocol {
        visibility,
        module,
        initial,
        states,
    } = protocol;
    let state_names = states.iter().map(|state| &state.name).collect::<Vec<_>>();
    let events = states
        .iter()
        .flat_map(|state| state.transitions.iter())
        .fold(BTreeMap::new(), |mut events, transition| {
            events
                .entry(transition.event.to_string())
                .or_insert(&transition.event);
            events
        })
        .into_values();
    let transition_arms = states.iter().flat_map(|state| {
        let source = &state.name;
        state.transitions.iter().map(move |transition| {
            let event = &transition.event;
            let target = &transition.target;
            quote!((RuntimeState::#source, Event::#event) => RuntimeState::#target)
        })
    });
    let choice_arms = states.iter().map(|state| {
        let name = &state.name;
        let choice = match state.choice {
            ChoiceKind::Internal => quote!(ChoiceKind::Internal),
            ChoiceKind::External => quote!(ChoiceKind::External),
        };
        quote!(RuntimeState::#name => #choice)
    });
    let typestate_impls = states.iter().map(|state| {
        let source = &state.name;
        let methods = state.transitions.iter().map(|transition| {
            let method = &transition.method;
            let target = &transition.target;
            quote! {
                #[must_use]
                pub const fn #method(self) -> Session<#target> {
                    Session { _phase: ::core::marker::PhantomData }
                }
            }
        });
        quote! {
            impl Session<#source> {
                #(#methods)*
            }
        }
    });
    let dual_typestate_impls = states.iter().map(|state| {
        let source = &state.name;
        let methods = state.transitions.iter().map(|transition| {
            let method = &transition.method;
            let target = &transition.target;
            quote! {
                #[must_use]
                pub const fn #method(self) -> DualSession<#target> {
                    DualSession { _phase: ::core::marker::PhantomData }
                }
            }
        });
        quote! {
            impl DualSession<#source> {
                #(#methods)*
            }
        }
    });
    let svg = railroad_svg(&states);
    let diagram_name = format_ident!("{}_RAILROAD_SVG", module.to_string().to_uppercase());

    Ok(quote! {
        #visibility mod #module {
            #(
                #[derive(Clone, Copy, Debug, Eq, PartialEq)]
                pub enum #state_names {}
            )*

            #[derive(Clone, Copy, Debug, Eq, PartialEq)]
            pub enum RuntimeState { #(#state_names),* }

            #[derive(Clone, Copy, Debug, Eq, PartialEq)]
            pub enum Event { #(#events),* }

            #[derive(Clone, Copy, Debug, Eq, PartialEq)]
            pub enum ChoiceKind { Internal, External }

            impl ChoiceKind {
                #[must_use]
                pub const fn dual(self) -> Self {
                    match self {
                        Self::Internal => Self::External,
                        Self::External => Self::Internal,
                    }
                }
            }

            #[derive(Clone, Copy, Debug, Eq, PartialEq)]
            pub struct TransitionError {
                pub state: RuntimeState,
                pub event: Event,
            }

            #[derive(Clone, Copy, Debug, Eq, PartialEq)]
            pub struct RuntimeFsm {
                state: RuntimeState,
            }

            impl RuntimeFsm {
                #[must_use]
                pub const fn new() -> Self {
                    Self { state: RuntimeState::#initial }
                }

                #[must_use]
                pub const fn state(&self) -> RuntimeState {
                    self.state
                }

                #[must_use]
                pub const fn choice(&self) -> ChoiceKind {
                    match self.state { #(#choice_arms),* }
                }

                #[must_use]
                pub const fn dual_choice(&self) -> ChoiceKind {
                    self.choice().dual()
                }

                pub fn step(&mut self, event: Event) -> Result<(), TransitionError> {
                    self.state = match (self.state, event) {
                        #(#transition_arms,)*
                        (state, event) => return Err(TransitionError { state, event }),
                    };
                    Ok(())
                }
            }

            impl Default for RuntimeFsm {
                fn default() -> Self { Self::new() }
            }

            #[must_use]
            #[derive(Clone, Copy, Debug, Eq, PartialEq)]
            pub struct Session<Phase> {
                _phase: ::core::marker::PhantomData<Phase>,
            }

            /// Typestate witness for the role dual to [`Session`].
            #[must_use]
            #[derive(Clone, Copy, Debug, Eq, PartialEq)]
            pub struct DualSession<Phase> {
                _phase: ::core::marker::PhantomData<Phase>,
            }

            impl Session<#initial> {
                #[must_use]
                pub const fn new() -> Self {
                    Self { _phase: ::core::marker::PhantomData }
                }
            }

            impl DualSession<#initial> {
                #[must_use]
                pub const fn new() -> Self {
                    Self { _phase: ::core::marker::PhantomData }
                }
            }

            #(#typestate_impls)*
            #(#dual_typestate_impls)*

            pub const #diagram_name: &str = #svg;
        }
    })
}

fn validate(protocol: &Protocol) -> Result<()> {
    let states = protocol
        .states
        .iter()
        .map(|state| state.name.to_string())
        .collect::<BTreeSet<_>>();
    if !states.contains(&protocol.initial.to_string()) {
        return Err(syn::Error::new(
            protocol.initial.span(),
            "initial state is not declared",
        ));
    }
    for state in &protocol.states {
        let mut methods = BTreeSet::new();
        for transition in &state.transitions {
            if !states.contains(&transition.target.to_string()) {
                return Err(syn::Error::new(
                    transition.target.span(),
                    "transition target is not declared",
                ));
            }
            if !methods.insert(transition.method.to_string()) {
                return Err(syn::Error::new(
                    transition.method.span(),
                    "duplicate transition method in state",
                ));
            }
        }
    }
    Ok(())
}

fn railroad_svg(states: &[State]) -> String {
    let alternatives = states
        .iter()
        .flat_map(|state| {
            state.transitions.iter().map(|transition| {
                let choice = match state.choice {
                    ChoiceKind::Internal => "⊕",
                    ChoiceKind::External => "&",
                };
                Box::new(Sequence::new(vec![
                    Box::new(NonTerminal::new(format!("{} {choice}", state.name))) as Box<dyn Node>,
                    Box::new(Terminal::new(transition.event.to_string())),
                    Box::new(NonTerminal::new(transition.target.to_string())),
                ])) as Box<dyn Node>
            })
        })
        .collect::<Vec<_>>();
    let root: Sequence<Box<dyn Node>> = Sequence::new(vec![
        Box::new(Start),
        Box::new(Choice::new(alternatives)),
        Box::new(End),
    ]);
    Diagram::new_with_stylesheet(root, &Stylesheet::Light).to_string()
}
