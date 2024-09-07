from app import app, db

# Create an application context
with app.app_context():
    db.create_all()
