<?php
set_include_path('/home/danbates/uni-compsec-back/');
include('helper.php');

checkSession();
//Homepage

function signInButton(): string
{
    return '
    <form class="d-flex justify-content-center" action="signin.php"><button class="btn btn-secondary m-1" id="sign-in" type="submit">Sign In</button></form>
    ';
}

function signOutButton(): string
{
    return '
    <form class="d-flex justify-content-center" method="post" action="home.php"><button class="btn btn-secondary m-1" id="sign-out" type="submit" name="SignOut">Sign Out</button></form>
    ';
}

function menu(): string
{
    $menu = '<a class="btn btn-primary m-1" href="requestevaluation.php">Request Evaluation</a>';
    $menu .= '<a class="btn btn-info m-1" href="recovery.php">Recovery Dashboard</a>';
    if (isUserAdmin()) {
        $menu .= '<a class="btn btn-secondary m-1" href="requestlist.php">List of Requests</a>';
    }
    return $menu;
}

echo pageTop();

if (isset($_POST['SignOut']) && isset($_SESSION['signedIn']) && $_SESSION['signedIn']) {
    quitSession(); //unset session vars and destroy the session
}

if (isUserSignedIn()) {
    echo signOutButton(); //User is signed in so give them the option to Sign Out
    echo menu();
} else {
    echo signInButton(); //User isn't signed in so give them the option
}

echo pageBottom();
