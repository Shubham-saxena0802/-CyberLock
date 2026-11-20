
#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sqlite3.h>

#pragma comment(lib, "ws2_32.lib")


#include <random>
#include <ctime>
#include <sstream>

// Generate a unique hexadecimal message ID
std::string generateMessageID() {
    std::random_device rd;
    std::ostringstream id;

    for (int i = 0; i < 32; i++) {
        id << std::hex << (rd() % 16);
    }

    return id.str();
}

// Save an encrypted package into SQLite
bool saveMessage(const std::string& messageID,
                 const std::string& encryptedPackage) {

    sqlite3* db;

    if (sqlite3_open("cyberlock.db", &db) != SQLITE_OK) {
        std::cout << "Database open failed!\n";
        sqlite3_close(db);
        return false;
    }

    const char* sql =
        "INSERT INTO messages (message_id, encrypted_package, created_at) "
        "VALUES (?, ?, datetime('now'));";

    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cout << "SQL preparation failed!\n";
        sqlite3_close(db);
        return false;
    }

    sqlite3_bind_text(stmt, 1, messageID.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, encryptedPackage.c_str(), -1, SQLITE_TRANSIENT);

    bool success = (sqlite3_step(stmt) == SQLITE_DONE);

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    if (success) {
        std::cout << "Encrypted message saved!\n";
    }

    return success;
}

bool getMessage(const std::string& messageID,
                std::string& encryptedPackage) {

    sqlite3* db;

    if (sqlite3_open("cyberlock.db", &db) != SQLITE_OK) {
        std::cout << "Database open failed!\n";
        return false;
    }

    const char* sql =
        "SELECT encrypted_package FROM messages WHERE message_id = ?;";

    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cout << "SQL preparation failed!\n";
        sqlite3_close(db);
        return false;
    }

    sqlite3_bind_text(stmt, 1, messageID.c_str(), -1, SQLITE_TRANSIENT);

    int result = sqlite3_step(stmt);

    if (result == SQLITE_ROW) {
        const unsigned char* data = sqlite3_column_text(stmt, 0);

        if (data != nullptr) {
            encryptedPackage =
                reinterpret_cast<const char*>(data);
        }

        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return true;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return false;
}


bool deleteMessage(const std::string& messageID) {
    sqlite3* db;

    if (sqlite3_open("cyberlock.db", &db) != SQLITE_OK) {
        std::cout << "Database open failed!\n";
        sqlite3_close(db);
        return false;
    }

    const char* sql =
        "DELETE FROM messages WHERE message_id = ?;";

    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cout << "SQL preparation failed!\n";
        sqlite3_close(db);
        return false;
    }

    sqlite3_bind_text(stmt, 1, messageID.c_str(), -1, SQLITE_TRANSIENT);

    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    bool deleted = success && sqlite3_changes(db) > 0;

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return deleted;
}


bool initializeDatabase() {
    sqlite3* db;

    if (sqlite3_open("cyberlock.db", &db) != SQLITE_OK) {
        std::cout << "Database connection failed!\n";
        return false;
    }

    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id TEXT UNIQUE NOT NULL,
            encrypted_package TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT
        );
    )";

    char* errorMessage = nullptr;

    if (sqlite3_exec(db, sql, nullptr, nullptr, &errorMessage) != SQLITE_OK) {
        std::cout << "Table creation failed: " << errorMessage << "\n";
        sqlite3_free(errorMessage);
        sqlite3_close(db);
        return false;
    }

    sqlite3_close(db);

    std::cout << "Database connected successfully!\n";
    std::cout << "Messages table ready!\n";

    return true;
}

int main() {
    // Start Windows networking
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cout << "Winsock initialization failed!\n";
        return 1;
    }

    if (!initializeDatabase()) {
    WSACleanup();
    return 1;
}   

    // Create server socket
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (serverSocket == INVALID_SOCKET) {
        std::cout << "Socket creation failed!\n";
        WSACleanup();
        return 1;
    }

    // Configure server address
    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    // Bind socket
    if (bind(serverSocket, (sockaddr*)&serverAddress,
             sizeof(serverAddress)) == SOCKET_ERROR) {
        std::cout << "Binding failed!\n";
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    // Start listening
    if (listen(serverSocket, 5) == SOCKET_ERROR) {
        std::cout << "Listening failed!\n";
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "CyberLock backend is running!\n";
    std::cout << "Listening on http://localhost:8080\n";
    std::cout << "Press Ctrl+C to stop.\n";

    // Accept incoming connections
       
while (true) {
    SOCKET clientSocket = accept(serverSocket, nullptr, nullptr);

    if (clientSocket == INVALID_SOCKET) {
        continue;
    }

    std::string request;
    char buffer[8192];

    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);

    if (bytesReceived > 0) {
        request.append(buffer, bytesReceived);

        // Find the end of the HTTP headers
        size_t headerEnd = request.find("\r\n\r\n");

        if (headerEnd != std::string::npos) {
            std::string headers = request.substr(0, headerEnd);
            std::string requestLine = headers.substr(0, headers.find("\r\n"));

            std::cout << "Request: " << requestLine << "\n";

            // Find Content-Length
            size_t contentLength = 0;
            size_t clPos = headers.find("Content-Length:");

            if (clPos != std::string::npos) {
                clPos += 15;
                while (clPos < headers.size() &&
                       headers[clPos] == ' ') {
                    clPos++;
                }

                contentLength = std::stoul(headers.substr(clPos));
            }

            // Read remaining request body
            size_t bodyStart = headerEnd + 4;

            while (request.size() - bodyStart < contentLength &&
                   request.size() < 1024 * 1024) {
                bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);

                if (bytesReceived <= 0) {
                    break;
                }

                request.append(buffer, bytesReceived);
            }

            std::string responseBody;
std::string status = "200 OK";
std::string responseContentType = "application/json";
if (requestLine.find("OPTIONS ") == 0) {

    status = "200 OK";
    responseContentType = "application/json";
    responseBody = R"({"status":"success"})";

}
else if (requestLine.find("GET /api/health ") == 0) {

    responseBody =
        R"({"status":"success","message":"CyberLock backend is running!"})";

}
else if (requestLine.find("GET /api/messages/") == 0) {

    std::string path = requestLine.substr(
        4, requestLine.find(" ", 4) - 4
    );

    std::string messageID = path.substr(
        std::string("/api/messages/").length()
    );

    std::string encryptedPackage;

    if (getMessage(messageID, encryptedPackage)) {
        responseBody = encryptedPackage;
        responseContentType = "text/plain";
    }
    else {
        status = "404 Not Found";
        responseBody = "Message not found";
        responseContentType = "text/plain";
    }

}
else if (requestLine.find("DELETE /api/messages/") == 0) {

    std::string path = requestLine.substr(
        7, requestLine.find(" ", 7) - 7
    );

    std::string messageID = path.substr(
        std::string("/api/messages/").length()
    );

    if (deleteMessage(messageID)) {
        status = "200 OK";
        responseBody =
            R"({"status":"success","message":"Message deleted"})";
    }
    else {
        status = "404 Not Found";
        responseBody =
            R"({"status":"error","message":"Message not found"})";
    }

}
else if (requestLine.find("POST /api/messages ") == 0) {

    if (request.size() - bodyStart >= contentLength &&
        contentLength > 0) {

        std::string encryptedPackage =
            request.substr(bodyStart, contentLength);

        std::string messageID = generateMessageID();

        if (saveMessage(messageID, encryptedPackage)) {
            responseBody =
                "{\"status\":\"success\",\"message_id\":\"" +
                messageID + "\"}";
        }
        else {
            status = "500 Internal Server Error";
            responseBody =
                R"({"status":"error","message":"Database save failed"})";
        }
    }
    else {
        status = "400 Bad Request";
        responseBody =
            R"({"status":"error","message":"Missing or incomplete body"})";
    }

}
else {

    status = "404 Not Found";
    responseBody =
        R"({"status":"error","message":"Route not found"})";

}

            std::string response =
                "HTTP/1.1 " + status + "\r\n"
               "Content-Type: " + responseContentType + "\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\n"
                "Access-Control-Allow-Headers: Content-Type\r\n"
                "Content-Length: " + std::to_string(responseBody.size()) +
                "\r\n"
                "Connection: close\r\n\r\n" +
                responseBody;

            send(clientSocket, response.c_str(),
                 static_cast<int>(response.size()), 0);
        }
    

    closesocket(clientSocket);
}

    }

    closesocket(serverSocket);
    WSACleanup();

    return 0;
}
