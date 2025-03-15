<?php
$mysqli = new mysqli("mysql", "root", "rootpassword", "vulnerable_db");

$data = json_decode(file_get_contents("php://input"), true);
$id = $data['id'] ?? null; // 从JSON数据中直接获取ID，不进行任何过滤
if ($id) {
    $query = "SELECT id, username FROM users WHERE id = $id"; // 直接将用户输入拼接到查询中
    $result = $mysqli->query($query);
    if ($result && $result->num_rows > 0) {
        while($row = $result->fetch_assoc()) {
            echo "id " . $row["id"] . " - Name: " . $row["username"] . "<br>";
        }
    } else {
        echo "SQL query failed or returned no results.";
    }
} else {
    echo "No ID provided.";
}
?>
