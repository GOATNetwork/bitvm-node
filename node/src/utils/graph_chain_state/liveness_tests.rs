use super::*;

#[tokio::test]
async fn confirmed_prekickoff_does_not_require_goat_graph_data() {
    let (goat, _) = GOATClient::new_mock_client();
    let graph_id = Uuid::new_v4();
    assert!(goat.gateway_get_graph_data(&graph_id).await.is_err());
    assert_eq!(
        initial_graph_stage(&goat, graph_id, true, false).await.unwrap(),
        GraphStatus::PreKickoff
    );
    assert!(initial_graph_stage(&goat, graph_id, false, false).await.is_err());
}
