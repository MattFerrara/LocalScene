# LocalScene

## Project Overview

LocalScene is a web-based platform designed to centralize and simplify the discovery and promotion of local concert events. The project aims to address the fragmentation of information in local music scenes by providing a single, intuitive hub for users to find upcoming shows and for artists and venues to submit their events. Key features include an interactive map for geographical discovery, a chronological list view, and a secure system for user authentication and concert submission.

## Features

  - Interactive Map View: Browse upcoming concerts on a map powered by Leaflet.js. Markers are clustered to improve performance and readability in dense areas.

  - Concert List View: A scrollable, chronological list of all upcoming shows for users who prefer a non-geographical Browse experience.

  - Secure User Authentication: Users can register for an account and log in securely. Password hashing is handled by Bcrypt, and authentication is managed with JSON Web Tokens (JWT). Email verification is required to prevent bot submissions.

  - Event Submission: Authenticated users can submit new concert details, including band, venue, date, time, and other information.

  - Data Enrichment: The backend automatically converts addresses to latitude and longitude coordinates using the Geocode.maps.co API and determines the correct timezone and UTC timestamp for each event using the Timezonedb API. This ensures accurate display and search functionality.

  - Automatic Deletion: Past concerts are automatically removed from the database one hour after their scheduled start time using a MongoDB TTL (Time-To-Live) index.

## Technology Stack

### Frontend

  - HTML, CSS, JavaScript: Vanilla web technologies for the user interface.

  - Leaflet.js: An open-source JavaScript library for mobile-friendly interactive maps.

  - Leaflet.markercluster: A plugin for efficient marker management and clustering.

### Backend

   - Node.js: The JavaScript runtime environment.

   - Express.js: A minimalist web framework for building the RESTful API.

   - MongoDB: A NoSQL database for storing concert and user data.

   - Bcrypt: For secure password hashing.

   - JSON Web Tokens (JWT): For stateless user authentication.

   - Nodemailer: For sending account verification emails.

## External Services

  - Geocode.maps.co: Geocoding API for converting addresses to coordinates.

  - Timezonedb: Timezone API for accurate time zone and UTC conversion.

## Local Setup

To set up and run the LocalScene project locally, follow these steps:

   - Clone the repository:
      - gh repo clone MattFerrara/LocalScene

   - Install dependencies:
      - npm install

   - Set up environment variables:
      - Create a .env file in the root directory and add the following variables, replacing the placeholder values with your own keys and configurations
     
    MONGO_URI="your_mongodb_connection_string"
    JWT_SECRET="your_secret_key"
    GEOCODE_KEY="your_geocode_api_key"
    TZDB_KEY="your_timezonedb_api_key"
    EMAIL_SERVICE_HOST="your_email_host"
    EMAIL_SERVICE_PORT="your_email_port"
    EMAIL_AUTH_USER="your_email_user"
    EMAIL_AUTH_PASS="your_email_password"

   - Run the server:
      - Navigate to the localscene folder that contains the server.js file and run the command
      - Node server.js

   - Run the frontend:
      - Navigate to the frontend directory and open the index.html file in your browser to view the application. The frontend is a static site and communicates with the backend API running locally.
