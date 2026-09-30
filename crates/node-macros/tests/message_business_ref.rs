use node_macros::MessageBusinessRef;

#[derive(Debug, Eq, PartialEq)]
enum BusinessRef {
    Instance { instance_id: u64 },
    Graph { instance_id: u64, graph_id: u64 },
    Unscoped,
}

trait HasBusinessRef {
    fn business_ref(&self) -> BusinessRef;
}

struct Payload {
    instance_id: u64,
    graph_id: u64,
}

#[allow(dead_code)]
#[derive(MessageBusinessRef)]
enum Message {
    #[business_ref(graph)]
    Graph(Payload),
    #[business_ref(instance)]
    Instance(Payload),
    #[business_ref(unscoped)]
    Unit,
    #[business_ref(unscoped)]
    Tuple(u8, u16),
    #[business_ref(unscoped)]
    Named { value: u8 },
}

#[test]
fn derives_the_expected_business_reference_for_every_scope() {
    assert_eq!(
        Message::Graph(Payload { instance_id: 7, graph_id: 11 }).business_ref(),
        BusinessRef::Graph { instance_id: 7, graph_id: 11 }
    );
    assert_eq!(
        Message::Instance(Payload { instance_id: 7, graph_id: 11 }).business_ref(),
        BusinessRef::Instance { instance_id: 7 }
    );
    assert_eq!(Message::Unit.business_ref(), BusinessRef::Unscoped);
    assert_eq!(Message::Tuple(1, 2).business_ref(), BusinessRef::Unscoped);
    assert_eq!(Message::Named { value: 1 }.business_ref(), BusinessRef::Unscoped);
}
