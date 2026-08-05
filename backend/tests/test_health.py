from app import create_app


def test_health_returns_ok():
    app = create_app({"TESTING": True})
    client = app.test_client()
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


def test_unknown_route_is_404_json_shape():
    app = create_app({"TESTING": True})
    client = app.test_client()
    resp = client.get("/api/nope")
    assert resp.status_code == 404
