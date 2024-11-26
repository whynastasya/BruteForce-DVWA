<?php
session_start();

define('MAX_ATTEMPTS', 5);
define('BLOCK_DURATION', 300); 

function isBlocked($username)
{
    if (!isset($_SESSION['login_attempts'][$username])) {
        return false;
    }
    $attempts = $_SESSION['login_attempts'][$username];
    if (count($attempts) < MAX_ATTEMPTS) {
        return false;
    }
    $firstAttemptTime = $attempts[0];
    if (time() - $firstAttemptTime < BLOCK_DURATION) {
        return true;
    }
    $_SESSION['login_attempts'][$username] = array_filter($attempts, function ($timestamp) {
        return time() - $timestamp < BLOCK_DURATION;
    });
    return false;
}

function logAttempt($username)
{
    if (!isset($_SESSION['login_attempts'][$username])) {
        $_SESSION['login_attempts'][$username] = [];
    }
    $_SESSION['login_attempts'][$username][] = time();
}

function registerUser($pdo, $username, $password)
{
    $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
    $stmt = $pdo->prepare("INSERT INTO users (user, password) VALUES (:user, :password)");
    $stmt->execute(['user' => $username, 'password' => $hashedPassword]);
}

function loginUser($pdo, $username, $password)
{
    if (isBlocked($username)) {
        die("Вы временно заблокированы. Попробуйте позже.");
    }

    $stmt = $pdo->prepare("SELECT password, avatar FROM users WHERE user = :user");
    $stmt->execute(['user' => $username]);
    $user = $stmt->fetch();

    if (!$user || !password_verify($password, $user['password'])) {
        logAttempt($username);
        die("Неверное имя пользователя или пароль.");
    }

    $_SESSION['username'] = $username;
    echo "<p>Welcome to the password protected area, {$username}!</p>";
    echo "<img src='" . htmlspecialchars($user['avatar']) . "' alt='Avatar'>";
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['Login'])) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    loginUser($pdo, $username, $password);
}
?>

