# Emergency Vehicle Tracking System (EVTS)

![EVTS System Illustration](static/images/hero-image.png)

**EVTS** is a full-stack web application designed to provide a real-time tracking and dispatch system for emergency vehicles. It connects users in need with the nearest available emergency personnel (drivers), facilitating faster response times in critical situations. The system features separate dashboards for users, drivers, and administrators, with live map tracking, ride request management, and direct communication capabilities.

---

## ✨ Features

The system is divided into three distinct roles, each with a tailored set of features:

#### 👤 User Features
- **Secure Registration & Login:** Users can create and access their accounts securely.
- **Live Map Dashboard:** View a real-time map displaying all available and approved emergency vehicles.
- **Fixed POI Display:** See the locations of critical infrastructure like hospitals and police stations pinned on the map.
- **Intelligent Dispatch:** Request help and have the system automatically find the nearest available driver based on a network graph (Dijkstra's algorithm), not just straight-line distance.
- **Request Timeout & Rerouting:** If a requested driver doesn't respond within 1 minutes, the system automatically cancels the request and dispatches the next nearest driver.
- **Real-time Status Updates:** Receive instant WebSocket notifications when a driver accepts, rejects, or completes a ride.
- **Temporary Live Chat:** Once a ride is accepted, a temporary chat box appears, allowing direct communication with the responding driver. The chat disappears when the ride is complete.
- **Ride History:** View a complete history of all past ride requests.

#### 🚑 Driver Features
- **Secure Registration with Admin Approval:** Drivers can register, but their accounts must be approved by an administrator before they can log in and become active.
- **Live Dashboard:** View pending ride requests from users on a real-time map interface.
- **Accept/Reject Requests:** Respond to incoming ride requests with a single click.
- **Real-time Routing:** Once a ride is accepted, a route is drawn on the map from the driver's current location to the user's location.
- **Live Chat:** Communicate directly with the user after accepting their request.
- **Profile Management:** Drivers can update their personal information and vehicle details.

#### 👑 Administrator Features
- **Secure Admin Dashboard:** A separate, secure panel for system management.
- **Driver Approval Workflow:** View a list of all pending driver registrations and approve them to make their accounts active.
- **User & Driver Management:** View lists of all registered users and drivers in the system.
- **Global Ride History:** Access a comprehensive log of all ride requests that have occurred on the platform.

---

## 🛠️ Technology Stack

This project is built with a modern, full-stack technology set:

- **Backend:**
  - **Framework:** [Flask](https://flask.palletsprojects.com/)
  - **Real-time Communication:** [Flask-SocketIO](https://flask-socketio.readthedocs.io/)
  - **Database:** [SQLAlchemy](https://www.sqlalchemy.org/) with [SQLite](https://www.sqlite.org/index.html)
  - **Password Security:** [Werkzeug](https://werkzeug.palletsprojects.com/) for password hashing
  - **Background Tasks:** [APScheduler](https://apscheduler.readthedocs.io/) for handling request timeouts
  - **Web Server:** [Eventlet](http://eventlet.net/)
- **Frontend:**
  - **Templating:** [Jinja2](https://jinja.palletsprojects.com/)
  - **Mapping Library:** [Leaflet.js](https://leafletjs.com/)
  - **Routing Machine:** [Leaflet Routing Machine](http://www.liedman.se/leaflet-routing-machine/)
  - **Styling:** HTML5 & CSS3
- **Core Algorithm:**
  - **Pathfinding:** Dijkstra's Algorithm for finding the shortest path in the service network graph.

---

## 🚀 Getting Started

Follow these instructions to get a local copy of the project up and running for development and testing purposes.

### Prerequisites

- Python 3.10+
- `pip` (Python package installer)
- A web browser

### Installation & Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/[TODO: Your-GitHub-Username]/[TODO: Your-Repo-Name].git
    cd [TODO: Your-Repo-Name]
    ```

2.  **Create and activate a virtual environment:**
    - On Windows:
      ```bash
      python -m venv .venv
      .\.venv\Scripts\activate
      ```
    - On macOS/Linux:
      ```bash
      python3 -m venv .venv
      source .venv/bin/activate
      ```

3.  **Install the required packages:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Initialize the Database:**
    This command creates the `database.db` file and all the necessary tables.
    ```bash
    flask init-db
    ```

5.  **Create the First Administrator Account:**
    This command populates the database with your first admin user. You can configure the credentials inside `app.py`.
    ```bash
    flask create-admin
    ```

6.  **Run the application:**
    ```bash
    python app.py
    ```

7.  **Access the application:**
    Open your web browser and navigate to `http://127.0.0.1:5000`.

### Using the System

- **Admin Login:** Use the credentials set up in the previous step (default: `admin@gmail.com` / `***********`) and select the "Admin" role.
- **Create a Driver:** Register a new account with the "Driver" role. Then, log in as the admin and approve the new driver from the admin dashboard.
- **Create a User:** Register a new account with the "User" role.
- **Test the Flow:** Log in as the user, go to the dashboard, and request a ride. Log in as the approved driver in a separate browser window to see the request come in live.

---

## 📄 License

This project is licensed under the [@munalthapa710]. See the `LICENSE.md` file for details.

---

## 📬 Contact

[Munal Thapa] - [munalthapa710@gmail.com]
