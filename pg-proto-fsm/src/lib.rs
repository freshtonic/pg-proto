//! Protocol grammar to typestate, runtime FSM, and railroad-diagram generation.

use std::collections::{BTreeMap, BTreeSet};

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use railroad::{
    Choice, Diagram, Empty, End, Node, NonTerminal, Repeat, Sequence, Start, Stylesheet, Terminal,
    VerticalGrid,
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
         <div class=\"pg-proto-railroad\" style=\"overflow-x: auto\">\n\
         {svg}\n\
         </div>\n\n\
         `⊕` denotes an internal choice made by this role; `&` denotes an \
         external choice offered by its peer. Repeated rails are protocol \
         self-loops and bracketed labels are cleanliness effects."
    );

    Ok(quote! {
        #[doc = #module_doc]
        #visibility mod #module {
            #(
                #[derive(Clone, Copy, Debug, Eq, PartialEq)]
                pub enum #state_names {}
            )*

            #(
                #[derive(Clone, Copy, Debug, Eq, PartialEq)]
                pub enum #cleanliness_names {}
            )*

            #[derive(Clone, Copy, Debug, Eq, PartialEq)]
            pub enum RuntimeState { #(#state_names),* }

            #[derive(Clone, Copy, Debug, Eq, PartialEq)]
            pub enum Event { #(#events),* }

            pub const ALL_EVENTS: &[Event] = &[#(Event::#events),*];

            #[derive(Clone, Copy, Debug, Eq, PartialEq)]
            pub enum ChoiceKind { Internal, External, Mixed }

            impl ChoiceKind {
                #[must_use]
                pub const fn dual(self) -> Self {
                    match self {
                        Self::Internal => Self::External,
                        Self::External => Self::Internal,
                        Self::Mixed => Self::Mixed,
                    }
                }
            }

            #[derive(Clone, Copy, Debug, Eq, PartialEq)]
            pub struct RuntimeTransition {
                pub source: RuntimeState,
                pub event: Event,
                pub target: RuntimeState,
                pub choice: ChoiceKind,
            }

            pub const TRANSITIONS: &[RuntimeTransition] = &[#(#transition_descriptors),*];

            #projection_functions

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

            #[derive(Clone, Copy, Debug, Eq, PartialEq)]
            pub struct TransitionError {
                pub state: RuntimeState,
                pub event: Event,
            }

            #[derive(Clone, Copy, Debug, Eq, PartialEq)]
            pub struct ProjectionError {
                pub state: RuntimeState,
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

            #[must_use = "dropping a generated typed session abandons its protocol state"]
            #[derive(Debug)]
            pub struct TypedSession<Transport, Phase, Cleanliness = ()> {
                transport: Transport,
                _state: ::core::marker::PhantomData<(Phase, Cleanliness)>,
            }

            #[must_use = "dropping a generated dual session abandons its protocol state"]
            #[derive(Debug)]
            pub struct DualTypedSession<Transport, Phase, Cleanliness = ()> {
                transport: Transport,
                _state: ::core::marker::PhantomData<(Phase, Cleanliness)>,
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

            impl<Transport, Cleanliness> TypedSession<Transport, #initial, Cleanliness> {
                #[must_use]
                pub const fn with_transport(transport: Transport) -> Self {
                    Self { transport, _state: ::core::marker::PhantomData }
                }
            }

            impl<Transport, Cleanliness> DualTypedSession<Transport, #initial, Cleanliness> {
                #[must_use]
                pub const fn with_transport(transport: Transport) -> Self {
                    Self { transport, _state: ::core::marker::PhantomData }
                }
            }

            impl<Transport, Phase, Cleanliness> TypedSession<Transport, Phase, Cleanliness> {
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

                #[must_use]
                pub fn into_transport(self) -> Transport {
                    self.transport
                }
            }

            impl<Transport, Phase, Cleanliness> DualTypedSession<Transport, Phase, Cleanliness> {
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
    let productions = states
        .iter()
        .map(|state| {
            let labelled = |transition: &Transition| {
                let choice = match transition.choice.unwrap_or(state.choice) {
                    ChoiceKind::Internal => "⊕",
                    ChoiceKind::External => "&",
                    ChoiceKind::Mixed => {
                        unreachable!("validated mixed transition has a direction")
                    }
                };
                let event = match &transition.payload {
                    Some(payload) => format!("{}: {}", transition.event, quote!(#payload)),
                    None => transition.event.to_string(),
                };
                match &transition.cleanliness {
                    Some(cleanliness) => {
                        format!("{choice} {event} [{cleanliness}]")
                    }
                    None => format!("{choice} {event}"),
                }
            };
            let self_loops = state
                .transitions
                .iter()
                .filter(|transition| transition.target == state.name)
                .map(|transition| Box::new(Terminal::new(labelled(transition))) as Box<dyn Node>)
                .collect::<Vec<_>>();
            let exits = state
                .transitions
                .iter()
                .filter(|transition| transition.target != state.name)
                .map(|transition| {
                    Box::new(Sequence::new(vec![
                        Box::new(Terminal::new(labelled(transition))) as Box<dyn Node>,
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
    let width = diagram.width();
    let height = diagram.height();
    diagram
        .attr("width".to_owned())
        .or_insert_with(|| width.to_string());
    diagram
        .attr("height".to_owned())
        .or_insert_with(|| height.to_string());
    diagram
        .attr("style".to_owned())
        .or_insert_with(|| "display: block; max-width: none".to_owned());

    // rustdoc feeds doc attributes through a Markdown parser. Newlines inside
    // the SVG's style element would be interpreted as Markdown paragraphs,
    // producing invalid CSS. Keeping the embedded SVG on one line makes it a
    // single raw HTML block while retaining intrinsic dimensions for scrolling.
    diagram.to_string().replace(['\r', '\n'], " ")
}
