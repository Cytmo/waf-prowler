<?php
if (isset($_FILES['file'])) {
    $target_dir = "/var/www/html/uploads/";
    // 获取上传文件的扩展名
    $fileExtension = pathinfo($_FILES["file"]["name"], PATHINFO_EXTENSION);
    
    // 检查扩展名是否包含特殊符号
    if (preg_match('/[\'";]/', $fileExtension)) {
        // 如果包含特殊符号，返回400状态码并显示错误信息
        http_response_code(400);
        echo "Invalid file extension.";
        exit;  // 终止脚本执行
    }

    // 生成完全随机文件名，并附加原文件扩展名
    $randomFileName = uniqid("", true) . '.' . $fileExtension;
    $target_file = $target_dir . $randomFileName;
    $public_path = "/uploads/" . $randomFileName; // 用于返回的公开路径

    if (move_uploaded_file($_FILES["file"]["tmp_name"], $target_file)) {
        // 上传成功，返回公开路径
        echo "File has been uploaded: " . $public_path;
    } else {
        // 上传失败，返回400状态码并显示错误信息
        http_response_code(400);
        echo "Sorry, there was an error uploading your file.";
    }
} else {
    // 没有文件被上传或字段不正确，返回400状态码并显示错误信息
    http_response_code(400);
    echo "No file uploaded or wrong field name.";
}
?>
