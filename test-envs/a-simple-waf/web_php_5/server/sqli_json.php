<?php
$mysqli = new mysqli("mysql", "root", "rootpassword", "vulnerable_db");

$data = json_decode(file_get_contents("php://input"), true);
if (!empty($data['id'])) {
    $id = $data['id'];
    $result = $mysqli->query("SELECT id, username FROM users WHERE id = $id");
    if ($result && $result->num_rows > 0) {
        http_response_code(200);
        while($row = $result->fetch_assoc()) {
            echo "id: " . $row["id"] . " - Name: " . $row["username"] . "<br>";
        }
    } else {
        http_response_code(400);
        echo "SQL query failed or returned no results.";
    }
} else {
    http_response_code(400);
    echo "No ID provided.";
}
?>
