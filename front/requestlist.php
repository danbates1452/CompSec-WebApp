<?php
//All Listings, Admin Only

set_include_path('/home/danbates/uni-compsec-back/');
include('helper.php');
checkSession();

echo pageTop();

function errorMessage() {
    return "<h1>Please make sure you're <a href='signin.php'>signed in</a> to view this page.</h1>";
}

function SQLite3ResultToArray(SQLite3Result $result): array
{
    $rows = [];
    while (($currentRow = $result->fetchArray(SQLITE3_ASSOC)) !== False) {
        $rows[] = $currentRow; //loop over each row in the result and add it to an array of rows
    }
    return $rows;
}

function makeTable(Array $data): string
{
    $table = '<div class="wrapper p-1 m-3"><table class="order-table table table-bordered"><thead><tr>';
    $row0 = $data[0]; //headers will be constant
    $headers = array_keys($row0);
    foreach ($headers as $header) {
        if ($header !== 'EmailAddress' && $header !== 'PhoneNumber') {
            $table.= '<th>'.$header.'</th>';
        }
    }
    $table.= '</tr></thead><tbody>';
    foreach ($data as $row) {
        $table.= '<tr>';
        $email = '';
        $phone = '';
        //foreach ($row as $item) { //values
        foreach ($row as $key=>$value) {
            if ($key == 'EmailAddress') {
                $email = $value;
            } else if ($key == 'PhoneNumber') {
                $phone = $value;
            } else if ($key == 'Contact') {
                if ($value === 1) {
                    $table .= '<td>' . $phone . '</td>';
                } else {
                    //$value == 0
                    $table .= '<td>' . $email . '</td>';
                }
            } else if ($key == 'Image') {
                $table .= '<td><img src="images/' . $value . '" alt="Not provided" width="400"/></td>';
            } else {
                $table .= '<td>'.$value.'</td>';
            }

        }
        $table.= '</tr>';
    }
    $table.= '</tbody></table></div>';
    return $table;
}

$db = getDatabase();
if (isUserAdmin()) {
    $getListingsQuery = $db->prepare("
        SELECT 
        ListingID as 'Listing #',
        UserID as 'User ID', 
        (SELECT Username FROM Users WHERE Users.UserID = Listings.UserID) as 'Username',
        (SELECT DisplayName FROM Users WHERE Users.UserID = Listings.UserID) as 'Display Name',
        (SELECT EmailAddress FROM Users WHERE Users.UserID = Listings.UserID) as 'EmailAddress',
        (SELECT PhoneNumber FROM Users WHERE Users.UserID = Listings.UserID) as 'PhoneNumber',
        PhoneOrEmail as 'Contact',
        Comments,
        ImageName as 'Image'
        FROM Listings");
    $getListingsQueryResult = $getListingsQuery->execute();
    if ($getListingsQueryResult) {
        echo makeTable(SQLite3ResultToArray($getListingsQueryResult));
    } else {
        echo '<h1>No Listings found</h1>';
    }
} else {
    echo errorMessage();
}

echo pageBottom();
