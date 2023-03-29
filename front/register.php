<?php
set_include_path('/backend-directory');
include('helper.php');
checkSession();
//Registration

function registrationForm(): string
{
    return '
    <form class="mb-4 ml-5 mr-5" action="register.php" method="post">
    <div class="form-group p-1">
        <label for="displayName">Preferred Name (What should we call you?) <small>(Required) Maximum 30 characters</small></label>
        <input class="form-control" name="displayName" required id="displayName" type="text" placeholder="John Smith" maxlength="30" size="10">
    </div>
    <div class="form-group p-1">
        <label for="username">Username <small>(Required) Maximum 30 characters</small></label>
        <input class="form-control" name="username" required id="username" type="text" placeholder="Username" maxlength="30" size="30">
    </div>
    <div class="form-group p-1">
        <label for="password">Password <small>(Required)<br>MUST contain at least 16 characters including uppercase, lowercase, numerical, and special characters. Maximum 30 characters</small></label>
        <input class="form-control" name="password" required id="password" type="text" placeholder="Password" pattern="'.getPasswordRegexJS().'" maxlength="30" size="30">
    </div>
    <div class="form-group p-1">
        <label for="emailAddress">Contact Email Address <small>(Required)</small></label>
        <input class="form-control" name="emailAddress" required id="emailAddress" type="email" placeholder="name@provider.domain" maxlength="254" size="30">
    </div>
    <div class="form-group p-1">
        <label for="phoneNumber">Contact Phone Number <small>(Required) 8-14 Characters</small></label>
        <input class="form-control" name="phoneNumber" required id="phoneNumber" type="tel" placeholder="+44 7123456789" pattern="'.getPhoneRegexJS().'" maxlength="14" size="14">
    </div>
    <div class="form-group p-1">
        <div class="h-captcha" data-sitekey="22353c5a-05f5-4f2f-9b3d-a644670de95c"></div>
    </div>
    <div class="d-flex justify-content-center">
        <button class="btn btn-primary m-1" type="submit" name="submit">Register</button>
        <a class="btn btn-secondary m-1" type="button" href="signin.php">Cancel</a>
    </div>
    </form>
    ';
}

//variable to store the html we're going to output all at once to avoid outputting before we can send different headers (for redirects)
$htmlOut = '';

if (isset($_POST['submit'])) { //if submitted
    if (verifyHCaptcha()) {
        $displayName = sanitise($_POST['displayName']);
        $username = sanitise($_POST['username']);
        $password = sanitise($_POST['password']);
        $emailAddress = sanitise($_POST['emailAddress']);
        $phoneNumber = sanitise($_POST['phoneNumber']);

        $passwordHash = password_hash($password, getHashingAlgo());

        //attributes that reasonably should be unique. excludes display name for obvious reason,
        //and password as with random salts there could be a conflict
        $uniqueAttributes = ["Username" => $username, "EmailAddress" => $emailAddress, "PhoneNumber" => $phoneNumber];
        $db = getDatabase();
        $allUnique = True;
        foreach ($uniqueAttributes as $name=>$value) {
            $query = $db->prepare("SELECT * FROM 'Users' WHERE '$name' = ?");
            $query->bindValue(1, $value);
            $queryResult = $query->execute();
            if ($queryResult->fetchArray(SQLITE3_ASSOC) === False) { //Query returns False if it fails.
                unset($uniqueAttributes[$name]); //remove attribute from the array for the case where another conflicts
            } else { //If not False, then there is a conflicting attribute
                $allUnique = False;
            }
        }

        //boolean that is only true if all entered attributes are in the correct specified format
        $correctFormat = strlen($username) <= 30 &&
            strlen($password) <= 30 &&
            preg_match(passwordRegex, $password) && //checks if password is >16, so we don't need to do that a second time
            filter_var($emailAddress, FILTER_VALIDATE_EMAIL) &&
            strlen($displayName) > 0 && strlen($displayName) <= 30 &&
            preg_match(phoneRegex, $phoneNumber)
        ;

        if (count($uniqueAttributes) !== 0) {
            $numberOfThings = count($uniqueAttributes) > 1 ? 'a few things': 'one thing';
            $htmlOut .= '<h3 id="alert alert-warning">Almost there! Just '.$numberOfThings.' to fix:';
            $htmlOut .= '<ul>';
            foreach ($uniqueAttributes as $name=>$value) {
                switch ($name) {
                    case 'Username':
                        $htmlOut .= "<li>The Username: $value is already in use.</li>";
                        break;
                    case 'EmailAddress':
                        $htmlOut .= "<li>The Email Address: $value is attached to another account on our system.</li>";
                        break;
                    case 'PhoneNumber':
                        $htmlOut .= "<li>The Phone Number: $value is already attached to an account on our system.</li>";
                        break;
                }
            }
            $htmlOut .= '</ul>';
            $htmlOut .= '</h3>';
        } else if (!$correctFormat) {
            $htmlOut .= '<h3 class="alert alert-warning">Please ensure all fields are the correct length and format.</h3>';
        } else { //if everything that must be unique is unique -> register them
            $activationKey = generateRandomKey();
            $activationURL = 'https://danbat.es/cs/uni-compsec/activate.php?activationKey='.$activationKey;
            $_SESSION['activationKey'] = $activationKey;
            $_SESSION['username'] = $username; //to identify the user on activation
            $_SESSION['displayName'] = $displayName; // for activation email
            $_SESSION['emailAddress'] = $emailAddress; // for activation email
            $activated = 0; //Activation Boolean

            $registrationQuery = $db->prepare("INSERT INTO 'Users' ('Username', 'Password', 'EmailAddress', 'PhoneNumber', 'DisplayName', 'Activated')
        VALUES (:un, :pw, :em, :pn, :dn, :ac)");
            $registrationQuery->bindValue(':un', $username);
            $registrationQuery->bindValue(':pw', $passwordHash);
            $registrationQuery->bindValue(':em', $emailAddress);
            $registrationQuery->bindValue(':pn', $phoneNumber);
            $registrationQuery->bindValue(':dn', $displayName);
            $registrationQuery->bindValue(':ac', $activated);

            $registrationQueryResult = $registrationQuery->execute();
            if ($registrationQueryResult !== False) { //if didn't fail

                $htmlOut .= '<h1>You\'re registered!</h1>';
                $htmlOut .= sendActivationEmail($displayName, $activationURL, $emailAddress);
                $htmlOut .= "<h2><a href='home.php'>Redirecting in 5 seconds...</a></h2>";
                header("refresh:5;url=home.php"); //redirect user back home in 5 seconds
            } else {
                $htmlOut .= genericErrorMessage();
            }
        }
    } else { //if hcaptcha verification fails
        $htmlOut .= "<h1>Sorry, we couldn't verify that you're a human, please try again later</h1>";
    }

    unset($_POST['submit']); //make sure resubmissions cannot occur
} else {
    $htmlOut .= registrationForm();
}
echo pageTop();
echo $htmlOut;
echo hCaptchaJS();
echo pageBottom();
