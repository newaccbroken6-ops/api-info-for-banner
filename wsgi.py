from app import app, startup

# Initialize the app on startup
startup()

if __name__ == '__main__':
    app.run(debug=True)