//! Protocol grammar to typestate, runtime FSM, and railroad-diagram generation.

use std::collections::{BTreeMap, BTreeSet};

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use railroad::{
    Choice, Diagram, Empty, End, Node, NonTerminal, Repeat, Sequence, Start, Stylesheet, Terminal,
    VerticalGrid,
    svg::{self, HDir},
};
use syn::{
    Ident, Pat, Result, Token, Type, Visibility, braced,
    parse::{Parse, ParseStream},
    parse_macro_input,
};

mod keyword {
    syn::custom_keyword!(initial);
    syn::custom_keyword!(messages);
}

struct Protocol {
    visibility: Visibility,
    module: Ident,
    initial: Ident,
    messages: Option<MessageTypes>,
    states: Vec<State>,
}

struct MessageTypes {
    internal: Type,
    external: Type,
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
    Mixed,
}

struct Transition {
    choice: Option<ChoiceKind>,
    event: Ident,
    method: Ident,
    payload: Option<Type>,
    target: Ident,
    cleanliness: Option<Ident>,
    projection: Option<Pat>,
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
        let messages = if content.peek(keyword::messages) {
            content.parse::<keyword::messages>()?;
            let message_content;
            braced!(message_content in content);
            let internal_name: Ident = message_content.parse()?;
            if internal_name != "internal" {
                return Err(syn::Error::new(internal_name.span(), "expected `internal`"));
            }
            message_content.parse::<Token![:]>()?;
            let internal = message_content.parse()?;
            message_content.parse::<Token![,]>()?;
            let external_name: Ident = message_content.parse()?;
            if external_name != "external" {
                return Err(syn::Error::new(external_name.span(), "expected `external`"));
            }
            message_content.parse::<Token![:]>()?;
            let external = message_content.parse()?;
            if message_content.peek(Token![,]) {
                message_content.parse::<Token![,]>()?;
            }
            Some(MessageTypes { internal, external })
        } else {
            None
        };
        let mut states = Vec::new();
        while !content.is_empty() {
            states.push(content.parse()?);
        }
        Ok(Self {
            visibility,
            module,
            initial,
            messages,
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
            "mixed" => ChoiceKind::Mixed,
            _ => {
                return Err(syn::Error::new(
                    choice_name.span(),
                    "expected `internal`, `external`, or `mixed` choice",
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
        let first: Ident = input.parse()?;
        let (choice, event) = match first.to_string().as_str() {
            "internal" => (Some(ChoiceKind::Internal), input.parse()?),
            "external" => (Some(ChoiceKind::External), input.parse()?),
            _ => (None, first),
        };
        let method_content;
        syn::parenthesized!(method_content in input);
        let method = method_content.parse()?;
        let payload = if method_content.peek(Token![:]) {
            method_content.parse::<Token![:]>()?;
            Some(method_content.parse()?)
        } else {
            None
        };
        if !method_content.is_empty() {
            return Err(method_content.error("unexpected transition method tokens"));
        }
        input.parse::<Token![=>]>()?;
        let target = input.parse()?;
        let cleanliness = if input.peek(syn::token::Bracket) {
            let content;
            syn::bracketed!(content in input);
            Some(content.parse()?)
        } else {
            None
        };
        let projection = if input.peek(Token![<=]) {
            input.parse::<Token![<=]>()?;
            Some(Pat::parse_multi(input)?)
        } else {
            None
        };
        Ok(Self {
            choice,
            event,
            method,
            payload,
            target,
            cleanliness,
            projection,
        })
    }
}

/// Generates typestate witnesses, a runtime FSM, and a railroad SVG from one grammar.
///
/// The grammar uses `Event(method) => NextState` transitions grouped by source
/// state. An optional `[Cleanliness]` replaces the orthogonal cleanliness index
/// on transport-carrying generated sessions.
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
        messages,
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
        .into_values()
        .collect::<Vec<_>>();
    let cleanliness_names = states
        .iter()
        .flat_map(|state| state.transitions.iter())
        .filter_map(|transition| transition.cleanliness.as_ref())
        .fold(BTreeMap::new(), |mut names, cleanliness| {
            names.entry(cleanliness.to_string()).or_insert(cleanliness);
            names
        })
        .into_values();
    let transition_descriptors = states.iter().flat_map(|state| {
        let source = &state.name;
        state.transitions.iter().map(move |transition| {
            let event = &transition.event;
            let target = &transition.target;
            let choice = match transition.choice.unwrap_or(state.choice) {
                ChoiceKind::Internal => quote!(ChoiceKind::Internal),
                ChoiceKind::External => quote!(ChoiceKind::External),
                ChoiceKind::Mixed => unreachable!("validated mixed transition has a direction"),
            };
            quote!(RuntimeTransition {
                source: RuntimeState::#source,
                event: Event::#event,
                target: RuntimeState::#target,
                choice: #choice,
            })
        })
    });
    let choice_arms = states.iter().map(|state| {
        let name = &state.name;
        let choice = match state.choice {
            ChoiceKind::Internal => quote!(ChoiceKind::Internal),
            ChoiceKind::External => quote!(ChoiceKind::External),
            ChoiceKind::Mixed => quote!(ChoiceKind::Mixed),
        };
        quote!(RuntimeState::#name => #choice)
    });
    let projection_functions = messages.as_ref().map(|messages| {
        let internal_type = &messages.internal;
        let external_type = &messages.external;
        let internal_arms = states.iter().flat_map(|state| {
            let source = &state.name;
            state.transitions.iter().filter_map(move |transition| {
                let choice = transition.choice.unwrap_or(state.choice);
                (matches!(choice, ChoiceKind::Internal))
                    .then_some(transition.projection.as_ref())
                    .flatten()
                    .map(|pattern| {
                        let event = &transition.event;
                        quote!((RuntimeState::#source, #pattern) => Some(Event::#event))
                    })
            })
        });
        let external_arms = states.iter().flat_map(|state| {
            let source = &state.name;
            state.transitions.iter().filter_map(move |transition| {
                let choice = transition.choice.unwrap_or(state.choice);
                (matches!(choice, ChoiceKind::External))
                    .then_some(transition.projection.as_ref())
                    .flatten()
                    .map(|pattern| {
                        let event = &transition.event;
                        quote!((RuntimeState::#source, #pattern) => Some(Event::#event))
                    })
            })
        });
        quote! {
            /// Projects a role-initiated wire message into its protocol event.
            #[must_use]
            pub fn project_internal(
                state: RuntimeState,
                message: &#internal_type,
            ) -> Option<Event> {
                match (state, message) {
                    #(#internal_arms,)*
                    _ => None,
                }
            }

            /// Projects a peer-initiated wire message into its protocol event.
            #[must_use]
            pub fn project_external(
                state: RuntimeState,
                message: &#external_type,
            ) -> Option<Event> {
                match (state, message) {
                    #(#external_arms,)*
                    _ => None,
                }
            }
        }
    });
    let phase_message_types = messages.as_ref().map_or_else(Vec::new, |messages| {
        let internal_type = &messages.internal;
        let external_type = &messages.external;

        states.iter().map(|state| {
            let state_name = &state.name;
            let internal_name = format_ident!("{}InternalMessage", state_name);
            let external_name = format_ident!("{}ExternalMessage", state_name);

            let directional = |kind: ChoiceKind, wire_type: &Type, type_name: &Ident| {
                let transitions = state
                    .transitions
                    .iter()
                    .filter(|transition| {
                        transition.projection.is_some()
                            && matches!(
                                (transition.choice.unwrap_or(state.choice), kind),
                                (ChoiceKind::Internal, ChoiceKind::Internal)
                                    | (ChoiceKind::External, ChoiceKind::External)
                            )
                    })
                    .collect::<Vec<_>>();
                let variants = transitions
                    .iter()
                    .map(|transition| &transition.event)
                    .collect::<Vec<_>>();
                let borrow_variants = variants.clone();
                let wrapper_names = transitions
                    .iter()
                    .map(|transition| {
                        format_ident!("{}{}{}TransitionMessage", state_name, transition.event, match kind {
                            ChoiceKind::Internal => "Internal",
                            ChoiceKind::External => "External",
                            ChoiceKind::Mixed => unreachable!("a message direction cannot be mixed"),
                        })
                    })
                    .collect::<Vec<_>>();
                let wrapper_definitions = wrapper_names.iter().zip(transitions.iter()).map(|(wrapper, transition)| {
                    let event = &transition.event;
                    let wrapper_projector = match kind {
                        ChoiceKind::Internal => quote!(project_internal),
                        ChoiceKind::External => quote!(project_external),
                        ChoiceKind::Mixed => unreachable!("a message direction cannot be mixed"),
                    };
                    quote! {
                        #[doc = concat!("Validated wire message for one legal `", stringify!(#state_name), "` transition.")]
                        pub struct #wrapper(#wire_type);

                        impl #wrapper {
                            /// Borrows the validated wire message.
                            #[must_use]
                            pub const fn as_wire(&self) -> &#wire_type {
                                &self.0
                            }

                            /// Returns the validated wire message.
                            #[must_use]
                            pub fn into_wire(self) -> #wire_type {
                                self.0
                            }

                            /// Mutates or replaces the wire value while preserving this transition variant.
                            ///
                            /// # Errors
                            ///
                            /// Returns the replacement when it no longer denotes this phase transition.
                            pub fn try_map_wire(
                                self,
                                map: impl FnOnce(#wire_type) -> #wire_type,
                            ) -> ::core::result::Result<Self, #wire_type> {
                                let message = map(self.0);
                                if #wrapper_projector(RuntimeState::#state_name, &message)
                                    == Some(Event::#event)
                                {
                                    Ok(Self(message))
                                } else {
                                    Err(message)
                                }
                            }
                        }
                    }
                });
                let enum_wrappers = wrapper_names.clone();
                let match_variants = transitions.iter().map(|transition| {
                    let event = &transition.event;
                    let wrapper = format_ident!("{}{}{}TransitionMessage", state_name, event, match kind {
                        ChoiceKind::Internal => "Internal",
                        ChoiceKind::External => "External",
                        ChoiceKind::Mixed => unreachable!("a message direction cannot be mixed"),
                    });
                    quote!(Some(Event::#event) => Ok(Self::#event(#wrapper(message))))
                });
                let wire_variants = variants
                    .iter()
                    .map(|event| quote!(Self::#event(message) => message.into_wire()));
                let event_variants = transitions.iter().map(|transition| {
                    let event = &transition.event;
                    quote!(Self::#event(_) => Event::#event)
                });
                let projector = match kind {
                    ChoiceKind::Internal => quote!(project_internal),
                    ChoiceKind::External => quote!(project_external),
                    ChoiceKind::Mixed => unreachable!("a message direction cannot be mixed"),
                };
                let direction = match kind {
                    ChoiceKind::Internal => "role-initiated",
                    ChoiceKind::External => "peer-initiated",
                    ChoiceKind::Mixed => unreachable!("a message direction cannot be mixed"),
                };
                let projection_name = format_ident!(
                    "{}{}Projection",
                    state_name,
                    match kind {
                        ChoiceKind::Internal => "Internal",
                        ChoiceKind::External => "External",
                        ChoiceKind::Mixed => unreachable!("a message direction cannot be mixed"),
                    }
                );
                let projection_method = match kind {
                    ChoiceKind::Internal => format_ident!("project_internal_message"),
                    ChoiceKind::External => format_ident!("project_external_message"),
                    ChoiceKind::Mixed => unreachable!("a message direction cannot be mixed"),
                };
                let projection_variants = transitions.iter().zip(wrapper_names.iter()).map(
                    |(transition, wrapper)| {
                        let event = &transition.event;
                        let target = &transition.target;
                        let cleanliness = transition.cleanliness.as_ref().map_or_else(
                            || quote!(SourceCleanliness),
                            |cleanliness| quote!(#cleanliness),
                        );
                        quote! {
                            #[doc = concat!("The [`Event::", stringify!(#event), "`] transition and its correctly typed next connection.")]
                            #event {
                                /// Connection after applying the selected message transition.
                                connection: Conn<Transport, #target, #cleanliness>,
                                /// Validated message which selected this transition.
                                message: #wrapper,
                                /// Retains the source cleanliness parameter even when replaced.
                                source_cleanliness: ::core::marker::PhantomData<SourceCleanliness>,
                            }
                        }
                    },
                );
                let projection_arms = transitions.iter().map(|transition| {
                    let event = &transition.event;
                    quote! {
                        #type_name::#event(message) => #projection_name::#event {
                            connection: TypedSession {
                                transport,
                                _state: ::core::marker::PhantomData,
                            },
                            message,
                            source_cleanliness: ::core::marker::PhantomData,
                        }
                    }
                });

                quote! {
                    #(#wrapper_definitions)*

                    #[doc = concat!("Owned ", #direction, " messages legal in [`", stringify!(#state_name), "`].")]
                    pub enum #type_name {
                        #(
                            #[doc = concat!("The [`Event::", stringify!(#variants), "`] transition.")]
                            #variants(#enum_wrappers),
                        )*
                    }

                    #[doc = concat!("Typed next-connection projection for [`", stringify!(#type_name), "`].")]
                    pub enum #projection_name<Transport, SourceCleanliness> {
                        #(#projection_variants,)*
                        #[doc(hidden)]
                        __Impossible {
                            never: ::core::convert::Infallible,
                            marker: ::core::marker::PhantomData<(Transport, SourceCleanliness)>,
                        },
                    }

                    impl<Transport, SourceCleanliness>
                        TypedSession<Transport, #state_name, SourceCleanliness>
                    {
                        #[doc = concat!("Projects one [`", stringify!(#type_name), "`] into its message-selected next connection.")]
                        #[must_use]
                        #[allow(unreachable_patterns)]
                        pub fn #projection_method(
                            self,
                            message: #type_name,
                        ) -> #projection_name<Transport, SourceCleanliness> {
                            let transport = self.transport;
                            match message {
                                #(#projection_arms,)*
                                _ => unreachable!(),
                            }
                        }
                    }

                    impl #type_name {
                        /// Returns the protocol event represented by this message.
                        #[must_use]
                        #[allow(unreachable_patterns)]
                        pub const fn event(&self) -> Event {
                            match self {
                                #(#event_variants,)*
                                _ => unreachable!(),
                            }
                        }

                        /// Borrows the underlying decoded wire message.
                        #[must_use]
                        #[allow(unreachable_patterns)]
                        pub const fn as_wire(&self) -> &#wire_type {
                            match self {
                                #(Self::#borrow_variants(message) => message.as_wire(),)*
                                _ => unreachable!(),
                            }
                        }

                        /// Returns the underlying decoded wire message.
                        #[must_use]
                        #[allow(unreachable_patterns)]
                        pub fn into_wire(self) -> #wire_type {
                            match self {
                                #(#wire_variants,)*
                                _ => unreachable!(),
                            }
                        }
                    }

                    impl ::core::convert::TryFrom<#wire_type> for #type_name {
                        type Error = #wire_type;

                        fn try_from(message: #wire_type) -> ::core::result::Result<Self, #wire_type> {
                            match #projector(RuntimeState::#state_name, &message) {
                                #(#match_variants,)*
                                _ => Err(message),
                            }
                        }
                    }

                    impl ::core::convert::From<#type_name> for #wire_type {
                        fn from(message: #type_name) -> Self {
                            message.into_wire()
                        }
                    }

                    impl ::core::convert::AsRef<#wire_type> for #type_name {
                        fn as_ref(&self) -> &#wire_type {
                            self.as_wire()
                        }
                    }
                }
            };

            let internal = directional(ChoiceKind::Internal, internal_type, &internal_name);
            let external = directional(ChoiceKind::External, external_type, &external_name);
            quote! {
                #internal
                #external
            }
        }).collect::<Vec<_>>()
    });
    let typestate_impls = states.iter().map(|state| {
        let source = &state.name;
        let methods = state.transitions.iter().map(|transition| {
            let method = &transition.method;
            let target = &transition.target;
            quote! {
                #[doc = concat!("Applies `", stringify!(#method), "` and enters [`", stringify!(#target), "`].")]
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
                #[doc = concat!("Applies the dual `", stringify!(#method), "` transition and enters [`", stringify!(#target), "`].")]
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
    let typed_session_impls = states.iter().map(|state| {
        let source = &state.name;
        let methods = state.transitions.iter().map(|transition| {
            let method = &transition.method;
            let target = &transition.target;
            let cleanliness = transition
                .cleanliness
                .as_ref()
                .map_or_else(|| quote!(Cleanliness), |cleanliness| quote!(#cleanliness));
            if let Some(payload) = &transition.payload {
                quote! {
                    #[doc = concat!("Handles the payload for `", stringify!(#method), "`; success enters [`", stringify!(#target), "`] and failure returns the unchanged session.")]
                    pub fn #method<Output, Error>(
                        mut self,
                        payload: #payload,
                        handle: impl FnOnce(
                            &mut Transport,
                            #payload,
                        ) -> ::core::result::Result<Output, Error>,
                    ) -> ::core::result::Result<
                        (TypedSession<Transport, #target, #cleanliness>, Output),
                        (Self, Error),
                    > {
                        match handle(&mut self.transport, payload) {
                            Ok(output) => Ok((TypedSession {
                                transport: self.transport,
                                _state: ::core::marker::PhantomData,
                            }, output)),
                            Err(error) => Err((self, error)),
                        }
                    }
                }
            } else {
                quote! {
                    #[doc = concat!("Applies `", stringify!(#method), "` and enters [`", stringify!(#target), "`].")]
                    #[must_use]
                    pub fn #method(self) -> TypedSession<Transport, #target, #cleanliness> {
                        TypedSession {
                            transport: self.transport,
                            _state: ::core::marker::PhantomData,
                        }
                    }
                }
            }
        });
        quote! {
            impl<Transport, Cleanliness> TypedSession<Transport, #source, Cleanliness> {
                #(#methods)*
            }
        }
    });
    let dual_typed_session_impls = states.iter().map(|state| {
        let source = &state.name;
        let methods = state.transitions.iter().map(|transition| {
            let method = &transition.method;
            let target = &transition.target;
            let cleanliness = transition
                .cleanliness
                .as_ref()
                .map_or_else(|| quote!(Cleanliness), |cleanliness| quote!(#cleanliness));
            if let Some(payload) = &transition.payload {
                quote! {
                    #[doc = concat!("Handles the dual payload for `", stringify!(#method), "`; success enters [`", stringify!(#target), "`] and failure returns the unchanged session.")]
                    pub fn #method<Output, Error>(
                        mut self,
                        payload: #payload,
                        handle: impl FnOnce(
                            &mut Transport,
                            #payload,
                        ) -> ::core::result::Result<Output, Error>,
                    ) -> ::core::result::Result<
                        (DualTypedSession<Transport, #target, #cleanliness>, Output),
                        (Self, Error),
                    > {
                        match handle(&mut self.transport, payload) {
                            Ok(output) => Ok((DualTypedSession {
                                transport: self.transport,
                                _state: ::core::marker::PhantomData,
                            }, output)),
                            Err(error) => Err((self, error)),
                        }
                    }
                }
            } else {
                quote! {
                    #[doc = concat!("Applies the dual `", stringify!(#method), "` transition and enters [`", stringify!(#target), "`].")]
                    #[must_use]
                    pub fn #method(self) -> DualTypedSession<Transport, #target, #cleanliness> {
                        DualTypedSession {
                            transport: self.transport,
                            _state: ::core::marker::PhantomData,
                        }
                    }
                }
            }
        });
        quote! {
            impl<Transport, Cleanliness> DualTypedSession<Transport, #source, Cleanliness> {
                #(#methods)*
            }
        }
    });
    let svg = railroad_svg(&states);
    let diagram_name = format_ident!("{}_RAILROAD_SVG", module.to_string().to_uppercase());
    let module_doc = format!(
        "Generated `{module}` protocol grammar.\n\n\
         ## Railroad diagram\n\n\
         <style>.width-limiter:has(.pg-proto-railroad) {{ max-width: none; }}</style>\n\
         <div class=\"pg-proto-railroad\" style=\"overflow-x: auto\">\n\
         {svg}\n\
         </div>\n\n\
         `▷` denotes a choice or action initiated by this role; `◁` denotes one \
         received from or offered by its peer. Repeated rails are protocol \
         self-loops and bracketed labels are cleanliness effects."
    );

    Ok(quote! {
        #[doc = #module_doc]
        #visibility mod #module {
            #(
                #[doc = concat!("Protocol phase marker for `", stringify!(#state_names), "`.")]
                #[derive(Clone, Copy, Debug, Eq, PartialEq)]
                pub enum #state_names {}
            )*

            #(
                #[doc = concat!("Cleanliness marker for `", stringify!(#cleanliness_names), "`.")]
                #[derive(Clone, Copy, Debug, Eq, PartialEq)]
                pub enum #cleanliness_names {}
            )*

            /// Runtime representation of a generated protocol phase.
            #[derive(Clone, Copy, Debug, Eq, PartialEq)]
            pub enum RuntimeState {
                #(#[doc = concat!("The [`", stringify!(#state_names), "`] phase.")] #state_names),*
            }

            /// Events accepted by the generated protocol grammar.
            #[derive(Clone, Copy, Debug, Eq, PartialEq)]
            pub enum Event {
                #(#[doc = concat!("The `", stringify!(#events), "` transition event.")] #events),*
            }

            /// Complete event alphabet for exhaustive and differential testing.
            pub const ALL_EVENTS: &[Event] = &[#(Event::#events),*];

            /// Which role selects a transition at a protocol state.
            #[derive(Clone, Copy, Debug, Eq, PartialEq)]
            pub enum ChoiceKind {
                /// This role selects the transition.
                Internal,
                /// The peer selects the transition.
                External,
                /// Legal transitions include choices by both roles.
                Mixed,
            }

            /// Directional operations on [`ChoiceKind`].
            impl ChoiceKind {
                /// Returns the choice direction seen by the peer role.
                #[must_use]
                pub const fn dual(self) -> Self {
                    match self {
                        Self::Internal => Self::External,
                        Self::External => Self::Internal,
                        Self::Mixed => Self::Mixed,
                    }
                }
            }

            /// One edge in the generated runtime transition table.
            #[derive(Clone, Copy, Debug, Eq, PartialEq)]
            pub struct RuntimeTransition {
                /// Phase from which the event is legal.
                pub source: RuntimeState,
                /// Event which advances the protocol.
                pub event: Event,
                /// Phase entered after the event.
                pub target: RuntimeState,
                /// Role which selects this event.
                pub choice: ChoiceKind,
            }

            /// Canonical runtime transition table generated from the grammar.
            pub const TRANSITIONS: &[RuntimeTransition] = &[#(#transition_descriptors),*];

            #projection_functions
            #(#phase_message_types)*

            /// Looks up one legal transition from `state` for `event`.
            #[must_use]
            pub fn transition(
                state: RuntimeState,
                event: Event,
            ) -> Option<RuntimeTransition> {
                TRANSITIONS
                    .iter()
                    .copied()
                    .find(|transition| transition.source == state && transition.event == event)
            }

            /// Rejected runtime transition with the unchanged state and event.
            #[derive(Clone, Copy, Debug, Eq, PartialEq)]
            pub struct TransitionError {
                /// State in which the event was rejected.
                pub state: RuntimeState,
                /// Event which was not legal in `state`.
                pub event: Event,
            }

            /// Failure to project or apply a wire message in a runtime state.
            #[derive(Clone, Copy, Debug, Eq, PartialEq)]
            pub struct ProjectionError {
                /// State in which projection or advancement failed.
                pub state: RuntimeState,
            }

            /// Executable runtime mirror of the generated typestate API.
            #[derive(Clone, Copy, Debug, Eq, PartialEq)]
            pub struct RuntimeFsm {
                state: RuntimeState,
            }

            /// Runtime state-machine construction, inspection, and advancement.
            impl RuntimeFsm {
                /// Creates an FSM in the grammar's initial state.
                #[must_use]
                pub const fn new() -> Self {
                    Self { state: RuntimeState::#initial }
                }

                /// Returns the current runtime phase.
                #[must_use]
                pub const fn state(&self) -> RuntimeState {
                    self.state
                }

                /// Returns who selects transitions in the current phase.
                #[must_use]
                pub const fn choice(&self) -> ChoiceKind {
                    match self.state { #(#choice_arms),* }
                }

                /// Returns the current phase's choice as seen by the peer.
                #[must_use]
                pub const fn dual_choice(&self) -> ChoiceKind {
                    self.choice().dual()
                }

                /// Returns the direction of one legal event from the current state.
                #[must_use]
                pub fn event_choice(&self, event: Event) -> Option<ChoiceKind> {
                    transition(self.state, event).map(|transition| transition.choice)
                }

                /// Returns the direction of one legal event for the dual role.
                #[must_use]
                pub fn dual_event_choice(&self, event: Event) -> Option<ChoiceKind> {
                    match self.event_choice(event) {
                        Some(choice) => Some(choice.dual()),
                        None => None,
                    }
                }

                /// Advances the FSM with `event` without changing it on error.
                pub fn step(&mut self, event: Event) -> Result<(), TransitionError> {
                    match transition(self.state, event) {
                        Some(transition) => {
                            self.state = transition.target;
                            Ok(())
                        }
                        None => Err(TransitionError {
                            state: self.state,
                            event,
                        }),
                    }
                }

                /// Projects a wire message using the current state, then advances.
                ///
                /// The projector is state-aware because one wire message can denote
                /// different protocol events in nested or mixed sessions.
                pub fn step_projected<Message>(
                    &mut self,
                    message: &Message,
                    project: impl FnOnce(RuntimeState, &Message) -> Option<Event>,
                ) -> Result<Event, ProjectionError> {
                    let state = self.state;
                    let event = project(state, message).ok_or(ProjectionError { state })?;
                    match self.step(event) {
                        Ok(()) => Ok(event),
                        Err(_) => Err(ProjectionError { state }),
                    }
                }
            }

            impl Default for RuntimeFsm {
                fn default() -> Self { Self::new() }
            }

            /// Zero-sized typestate witness for this protocol role.
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

            /// Transport-carrying typestate for this protocol role.
            #[must_use = "dropping a generated typed session abandons its protocol state"]
            #[derive(Debug)]
            pub struct TypedSession<Transport, Phase, Cleanliness = ()> {
                transport: Transport,
                _state: ::core::marker::PhantomData<(Phase, Cleanliness)>,
            }

            /// Generated connection carrying transport, protocol phase, and cleanliness.
            pub type Conn<Transport, Phase, Cleanliness = ()> =
                TypedSession<Transport, Phase, Cleanliness>;

            /// Transport-carrying typestate for the peer role.
            #[must_use = "dropping a generated dual session abandons its protocol state"]
            #[derive(Debug)]
            pub struct DualTypedSession<Transport, Phase, Cleanliness = ()> {
                transport: Transport,
                _state: ::core::marker::PhantomData<(Phase, Cleanliness)>,
            }

            impl Session<#initial> {
                /// Creates a witness in the grammar's initial phase.
                #[must_use]
                pub const fn new() -> Self {
                    Self { _phase: ::core::marker::PhantomData }
                }
            }

            impl DualSession<#initial> {
                /// Creates a dual witness in the grammar's initial phase.
                #[must_use]
                pub const fn new() -> Self {
                    Self { _phase: ::core::marker::PhantomData }
                }
            }

            impl<Transport, Cleanliness> TypedSession<Transport, #initial, Cleanliness> {
                /// Attaches `transport` to a session in the initial phase.
                #[must_use]
                pub const fn with_transport(transport: Transport) -> Self {
                    Self { transport, _state: ::core::marker::PhantomData }
                }
            }

            impl<Transport, Cleanliness> DualTypedSession<Transport, #initial, Cleanliness> {
                /// Attaches `transport` to a dual session in the initial phase.
                #[must_use]
                pub const fn with_transport(transport: Transport) -> Self {
                    Self { transport, _state: ::core::marker::PhantomData }
                }
            }

            impl<Transport, Phase, Cleanliness> TypedSession<Transport, Phase, Cleanliness> {
                /// Replaces the transport representation without changing protocol indices.
                #[must_use]
                pub fn map_transport<Next>(
                    self,
                    map: impl FnOnce(Transport) -> Next,
                ) -> TypedSession<Next, Phase, Cleanliness> {
                    TypedSession {
                        transport: map(self.transport),
                        _state: ::core::marker::PhantomData,
                    }
                }

                /// Deliberately leaves the generated typestate API and returns its transport.
                #[must_use]
                pub fn into_transport(self) -> Transport {
                    self.transport
                }
            }

            impl<Transport, Phase, Cleanliness> DualTypedSession<Transport, Phase, Cleanliness> {
                /// Replaces the dual transport representation without changing protocol indices.
                #[must_use]
                pub fn map_transport<Next>(
                    self,
                    map: impl FnOnce(Transport) -> Next,
                ) -> DualTypedSession<Next, Phase, Cleanliness> {
                    DualTypedSession {
                        transport: map(self.transport),
                        _state: ::core::marker::PhantomData,
                    }
                }

                /// Deliberately leaves the generated dual API and returns its transport.
                #[must_use]
                pub fn into_transport(self) -> Transport {
                    self.transport
                }
            }

            #(#typestate_impls)*
            #(#dual_typestate_impls)*
            #(#typed_session_impls)*
            #(#dual_typed_session_impls)*

            /// Raw SVG embedded in this module's railroad-diagram documentation.
            pub const #diagram_name: &str = #svg;
        }
    })
}

fn validate(protocol: &Protocol) -> Result<()> {
    if protocol.messages.is_none()
        && let Some(transition) = protocol
            .states
            .iter()
            .flat_map(|state| &state.transitions)
            .find(|transition| transition.projection.is_some())
    {
        return Err(syn::Error::new(
            transition.event.span(),
            "transition projection requires a `messages` declaration",
        ));
    }
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
        match state.choice {
            ChoiceKind::Mixed
                if state
                    .transitions
                    .iter()
                    .any(|transition| transition.choice.is_none()) =>
            {
                return Err(syn::Error::new(
                    state.name.span(),
                    "every transition in a mixed state needs `internal` or `external`",
                ));
            }
            ChoiceKind::Internal | ChoiceKind::External
                if state
                    .transitions
                    .iter()
                    .any(|transition| transition.choice.is_some()) =>
            {
                return Err(syn::Error::new(
                    state.name.span(),
                    "transition directions are only valid in a mixed state",
                ));
            }
            _ => {}
        }
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
    const SVG_GUTTER: i64 = 12;

    let productions = states
        .iter()
        .map(|state| {
            let self_loops = state
                .transitions
                .iter()
                .filter(|transition| transition.target == state.name)
                .map(|transition| transition_node(transition, state.choice))
                .collect::<Vec<_>>();
            let exits = state
                .transitions
                .iter()
                .filter(|transition| transition.target != state.name)
                .map(|transition| {
                    Box::new(Sequence::new(vec![
                        transition_node(transition, state.choice),
                        Box::new(NonTerminal::new(transition.target.to_string())),
                    ])) as Box<dyn Node>
                })
                .collect::<Vec<_>>();
            let mut nodes = vec![
                Box::new(Start) as Box<dyn Node>,
                Box::new(NonTerminal::new(state.name.to_string())),
            ];
            if !self_loops.is_empty() {
                nodes.push(Box::new(Repeat::new(Choice::new(self_loops), Empty)));
            }
            if exits.is_empty() {
                nodes.push(Box::new(Terminal::new("end".to_owned())));
            } else {
                nodes.push(Box::new(Choice::new(exits)));
            }
            nodes.push(Box::new(End));
            Box::new(Sequence::new(nodes)) as Box<dyn Node>
        })
        .collect::<Vec<_>>();
    let root = VerticalGrid::new(productions);
    let mut diagram = Diagram::new_with_stylesheet(root, &Stylesheet::Light);
    diagram.add_css(
        "svg.railroad a.link tspan { text-decoration: underline; } \
         svg.railroad a.link:hover tspan { text-decoration-thickness: 2px; }",
    );
    let content_width = diagram.width();
    let content_height = diagram.height();
    let width = content_width + SVG_GUTTER;
    let height = content_height + SVG_GUTTER;
    diagram
        .attr("width".to_owned())
        .or_insert_with(|| width.to_string());
    diagram
        .attr("height".to_owned())
        .or_insert_with(|| height.to_string());
    diagram
        .attr("style".to_owned())
        .or_insert_with(|| "display: block; max-width: none".to_owned());
    diagram
        .attr("data-content-width".to_owned())
        .or_insert_with(|| content_width.to_string());
    diagram
        .attr("data-content-height".to_owned())
        .or_insert_with(|| content_height.to_string());

    let svg = diagram.to_string().replace(
        &format!("viewBox=\"0 0 {content_width} {content_height}\""),
        &format!("viewBox=\"0 0 {width} {height}\""),
    );

    // rustdoc feeds doc attributes through a Markdown parser. Newlines inside
    // the SVG's style element would be interpreted as Markdown paragraphs,
    // producing invalid CSS. Keeping the embedded SVG on one line makes it a
    // single raw HTML block while retaining intrinsic dimensions for scrolling.
    svg.replace(['\r', '\n'], " ")
}

fn transition_node(transition: &Transition, state_choice: ChoiceKind) -> Box<dyn Node> {
    let choice = match transition.choice.unwrap_or(state_choice) {
        ChoiceKind::Internal => "▷",
        ChoiceKind::External => "◁",
        ChoiceKind::Mixed => unreachable!("validated mixed transition has a direction"),
    };
    let cleanliness = transition
        .cleanliness
        .as_ref()
        .map_or_else(String::new, |cleanliness| format!(" [{cleanliness}]"));
    let (prefix, payload, suffix, url) = match &transition.payload {
        Some(payload) => {
            let rendered = quote!(#payload).to_string().replace(' ', "");
            (
                format!("{choice} {}(", transition.event),
                Some(rendered),
                format!("){cleanliness}"),
                payload_doc_url(payload),
            )
        }
        None => (
            format!("{choice} {}", transition.event),
            None,
            cleanliness,
            None,
        ),
    };
    Box::new(TransitionTerminal {
        prefix,
        payload,
        suffix,
        url,
    })
}

#[derive(Debug)]
struct TransitionTerminal {
    prefix: String,
    payload: Option<String>,
    suffix: String,
    url: Option<String>,
}

impl TransitionTerminal {
    fn label_width(&self) -> usize {
        self.prefix.chars().count()
            + self
                .payload
                .as_ref()
                .map_or(0, |value| value.chars().count())
            + self.suffix.chars().count()
    }
}

impl Node for TransitionTerminal {
    fn entry_height(&self) -> i64 {
        11
    }

    fn height(&self) -> i64 {
        22
    }

    fn width(&self) -> i64 {
        i64::try_from(self.label_width()).expect("transition label width fits i64") * 9 + 24
    }

    fn draw(&self, x: i64, y: i64, _h_dir: HDir) -> svg::Element {
        let rect = svg::Element::new("rect")
            .set("x", &x)
            .set("y", &y)
            .set("height", &self.height())
            .set("width", &self.width())
            .set("rx", &10)
            .set("ry", &10);
        let mut text = svg::Element::new("text")
            .set("x", &(x + self.width() / 2))
            .set("y", &(y + self.entry_height() + 5));
        text.push(svg::Element::new("tspan").text(&self.prefix));
        if let Some(payload) = &self.payload {
            let payload = svg::Element::new("tspan").text(payload);
            match &self.url {
                Some(url) => {
                    text.push(
                        svg::Element::new("a")
                            .set("xlink:href", url)
                            .set("class", &"link")
                            .add(payload),
                    );
                }
                None => {
                    text.push(payload);
                }
            }
        }
        text.push(svg::Element::new("tspan").text(&self.suffix));
        svg::Element::new("g")
            .set("class", &"terminal")
            .add(rect)
            .add(text)
    }
}

fn payload_doc_url(payload: &Type) -> Option<String> {
    let payload = quote!(#payload).to_string().replace(' ', "");
    if payload.contains("bytes::Bytes") {
        return Some("https://docs.rs/bytes/1/bytes/struct.Bytes.html".to_owned());
    }
    let (module, name) = payload.strip_prefix("crate::")?.rsplit_once("::")?;
    let kind = match (module, name) {
        ("codec", "BackendMessage" | "TransactionStatus") => "enum",
        ("codec", _) | ("server_auth", "SaslInitialResponse") | ("startup", "StartupMessage") => {
            "struct"
        }
        _ => return None,
    };
    Some(format!("../../{module}/{kind}.{name}.html"))
}
