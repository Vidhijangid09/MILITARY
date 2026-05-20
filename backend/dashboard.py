from backend import db
from bson.json_util import dumps

users = db['users']
messages = db['messages']
alerts = db['threat_alerts']
audit = db['audit_logs']

# Build a dashboard summary for the front-end view.
def get_dashboard_stats() -> dict:
    return {
        'active_users': users.count_documents({}),
        'total_messages': messages.count_documents({}),
        'threat_alerts': alerts.count_documents({}),
        'suspicious_logins': audit.count_documents({'action': {'$in': ['failed_login', 'lockout']}}),
    }

# Return recent network logs for admin monitoring.
def get_network_logs() -> list:
    logs = list(audit.find({'action': {'$in': ['threat_detected', 'send_message', 'login', 'failed_login', 'lockout']}}, {'_id': 0}).sort('timestamp', -1).limit(50))
    return logs

# Provide data that can be used in chart analytics.
def get_traffic_summary() -> dict:
    recent_alerts = alerts.find().sort('timestamp', -1).limit(20)
    alert_history = [{'timestamp': str(alert['timestamp']), 'score': alert['score']} for alert in recent_alerts]
    message_counts = messages.aggregate([
        {'$group': {'_id': {'$dayOfMonth': '$created_at'}, 'count': {'$sum': 1}}},
        {'$sort': {'_id': 1}}
    ])
    volume_data = [{'day': entry['_id'], 'count': entry['count']} for entry in message_counts]
    return {
        'alert_history': alert_history,
        'message_volume': volume_data,
        'user_activity': users.count_documents({}),
    }

# Provide recent alerts for the UI cards.
def get_recent_alerts() -> list:
    return list(alerts.find({}, {'_id': 0}).sort('timestamp', -1).limit(10))
