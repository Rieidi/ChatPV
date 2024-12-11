# ChatPv

ChatPv is a desktop application for sending and receiving encrypted messages using MongoDB as the backend. This project is developed with **CustomTkinter** for the graphical interface and implements AES encryption for secure communication. But it only works on Windows for now...

## Features

- **Message Encryption**: All messages are encrypted using AES (Advanced Encryption Standard).
- **MongoDB Integration**: Connects to MongoDB for message and file storage.
- **Notifications**: Displays notifications for new incoming messages.
- **File Upload and Download**: Send and receive files directly through the interface.
- **Login Lockout**: Locks access after multiple failed authentication attempts.

## Technologies Used

- **Python 3.12**
- **CustomTkinter**: Modern and customizable graphical interface.
- **PyMongo**: Integration with MongoDB.
- **PyCryptodome**: For message encryption and decryption.
- **Plyer**: For system notifications.

## Installation Windows

1. Clone this repository:
   ```
   git clone https://github.com/Rieidi/ChatPV
   cd chatPV
   ```

2. Install the dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Set up MongoDB:
   - Ensure MongoDB is running.
   - Create a database and a collection to store messages.

4. Run the program:
   ```
   python ChatPV.py
   ```

## Installation Linux:

1. Clone this repository:
   ```
   git clone https://github.com/Rieidi/ChatPV
   cd chatPV
   ```
   
2. Create Venv
   ```
   sudo python3 -m Venv .
   ```

3. Activate Venv
   ```
   source bin/activate
   ```

4. Install requirements
   ```
   pip install -r requirements.txt
   sudo apt-get install python3-tk
   ```

5. Set up MongoDB:
   - Ensure MongoDB is running.
   - Create a database and a collection to store messages.

6. Run
   ```
   python3 ChatPV.py
   ```
   
## Initial Setup

On the first run, you will need to fill in the following fields:

- **MongoDB URI**: Connection string to your database (without the password).
  
   -mongodb+srv://[username:passwordhere@]host[/[defaultauthdb][?options]] 
- **Database Name**: The name of the database you created in MongoDB.
- **Collection Name**: The collection where messages will be stored.
- **Encryption Key**: Hexadecimal key for AES encryption (16 bytes/128 bits).
- **Username and Password**: Credentials for database authentication.

## Usage Examples

### Sending Messages
1. Type the message in the input field.
2. Press **Enter** or click **Send**.

### Uploading Files
1. Click **Upload File** in the menu.
2. Select the file you want to send.

### Downloading Files
1. Click the **Download** button next to the message containing the file.
2. Choose where to save the file.

## Security

- All messages are encrypted before being stored in the database.
- Implements an automatic lockout after 3 incorrect password attempts.

## License

This project is licensed under the [GNU GENERAL PUBLIC LICENSE v3.0](LICENSE).
