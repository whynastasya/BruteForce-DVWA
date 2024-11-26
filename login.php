<?php

if( isset( $_GET[ 'Login' ] ) ) {
	$user = $_GET[ 'username' ]; // CWE-89: Возможность SQL-инъекции.
	$pass = $_GET[ 'password' ]; // CWE-89: Возможность SQL-инъекции.
	$pass = md5( $pass ); // CWE-327: Используется устаревший и небезопасный алгоритм MD5.

	// Check the database
	$query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';"; // CWE-89: SQL-инъекция.
	$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( 
		'<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : 
		(($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>'
	); 
	// CWE-209: Ошибки базы данных выводятся пользователю напрямую.

	if( $result && mysqli_num_rows( $result ) == 1 ) {
		// Get users details
		$row    = mysqli_fetch_assoc( $result );
		$avatar = $row["avatar"]; // CWE-73: Аватар может содержать недопустимые или вредоносные данные.
		// Login successful
		$html .= "<p>Welcome to the password protected area {$user}</p>"; // CWE-79: Не экранирован вывод $user.
		$html .= "<img src=\"{$avatar}\" />"; // CWE-79: Не экранирован вывод $avatar.
	}
	else {
		// Login failed
		$html .= "<pre><br />Username and/or password incorrect.</pre>";
		// CWE-307: Отсутствует защита от brute-force атак.
	}
	((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res); 
	// CWE-526: Глобальная переменная используется для подключения к базе данных.
}
?>
