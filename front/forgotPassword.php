<?php
set_include_path('/home/danbates/uni-compsec-back/');
include('helper.php');

checkSession();
$htmlOut = ''; //variable to store the html we're going to output all at once to avoid outputting before we can send different headers (for redirects)

function forgotPasswordForm(): string
{
    return '
    <form action="forgotPassword.php" method="post">
        <div class="form-group p-1">
            <label for="emailAddress">The Registered or Recovery Email Address for the account you wish to recover</label>
            <input class="form-control" name="emailAddress" required id="emailAddress" type="email" placeholder="name@provider.domain" maxlength="254" size="30">
            
            <button class="btn btn-primary m-1" type="submit" name="submitForgotPassword">Submit</button>
        </div>
    </form>
    ';
}

function resetPasswordForm(): string
{
    if (isset($_SESSION['fpQuestion'])) {
        $questionInput = '
            <label for="securityAnswer">'.$_SESSION['fpQuestion'].'</label>
            <input class="form-control" name="securityAnswer" required id="securityAnswer" type="text">
        ';
    } else {
        $questionInput = '';
    }
    return '
    <form action="forgotPassword.php" method="post">
        <div class="form-group p-1">
            <label for="newPassword">Enter a new password for your account</label>
            <input class="form-control" name="newPassword" required id="newPassword" type="text" placeholder="New Password" pattern="'.getPasswordRegexJS().'" maxlength="30" size="30">
            '.$questionInput.'
            <button class="btn btn-primary m-1" type="submit" name="submitResetPassword">Submit</button>
        </div>
    </form>
    ';
}


if (isset($_POST['submitForgotPassword'])) {
    //if user has just submitted that they forgot their password
    $emailAddress = sanitise($_POST['emailAddress']);
    if (filter_var($emailAddress, FILTER_VALIDATE_EMAIL)) {
        //if a valid email address
        //check if in database and grab relevant user id
        $attributesQuery = getDatabase()->prepare("SELECT * FROM Users where EmailAddress = ?");
        $attributesQuery->bindValue(1, $emailAddress);
        $attributesQueryResult = $attributesQuery->execute();
        $userAttributesArray = $attributesQueryResult->fetchArray(SQLITE3_ASSOC);

        if (!$userAttributesArray) {
            //for recovery email
            $attributesQuery = getDatabase()->prepare("SELECT * FROM Users where RecoveryEmail = ?");
            $attributesQuery->bindValue(1, $emailAddress);
            $attributesQueryResult = $attributesQuery->execute();
            $userAttributesArray = $attributesQueryResult->fetchArray(SQLITE3_ASSOC);
        }

        if ($userAttributesArray && ($userAttributesArray['EmailAddress'] === $emailAddress || $userAttributesArray['RecoveryEmail'] === $emailAddress)) {
            //email address is correct and exists in DB, or is a recovery Email

            //retrieve security questions and answers
            $q1 = $userAttributesArray['Q1'];
            $q2 = $userAttributesArray['Q2'];
            $q3 = $userAttributesArray['Q3'];
            $a1 = $userAttributesArray['A1'];
            $a2 = $userAttributesArray['A2'];
            $a3 = $userAttributesArray['A3'];

            $questionArray = array($q1, $q2, $q3);
            $answerArray = array($a1, $a2, $a3);

            $canServeSecurityQuestion = !(in_array(null, $questionArray) || in_array(null, $answerArray));

            if ($canServeSecurityQuestion) {
                $randomSelector = rand(0, 2);
                $questionID = $questionArray[$randomSelector];
                $answer = $answerArray[$randomSelector];

                $questionString = getSecurityQuestions()[$questionID];

                $_SESSION['fpQuestion'] = $questionString;
                $_SESSION['fpAnswer'] = $answer;
            }

            //generate token
            $fpToken = generateRandomKey();
            $fpURL = 'https://danbat.es/cs/uni-compsec/forgotPassword.php?fpToken='.$fpToken;
            //set session variables to allow reset
            $_SESSION['fpToken'] = $fpToken;
            $_SESSION['fpTargetUserID'] = $userAttributesArray['UserID'];

            //finally, send the email
            $htmlOut .= sendPasswordRecoveryEmail($fpURL, $emailAddress);
            unset($_POST['submitForgotPassword']); //avoid resubmissions
        } else {
            $htmlOut .= '<h3>User not found, please enter an email address registered with us</h3>';
        }
    } else {
        $htmlOut .= '<h3>Please enter a valid email</h3>';
    }
} else if (isset($_GET['fpToken']) && isset($_SESSION['fpToken'])) {
    if (isset($_POST['submitResetPassword'])) {

        if (sanitise($_GET['fpToken']) === $_SESSION['fpToken']) {
            //correct token
            if (isset($_SESSION['fpQuestion'])) {
                if ($_SESSION['fpAnswer'] === sanitise($_POST['securityAnswer'])) {
                    //correct answer
                    $securityQuestionPassed = True;
                } else {
                    $htmlOut .= '<h3>Incorrect answer</h3>';
                }
            }

            if (isset($securityQuestionPassed) && $securityQuestionPassed) {
                $password = sanitise($_POST['newPassword']);
                if (preg_match(passwordRegex, $password)) {
                    $passwordHash = password_hash($password, getHashingAlgo());

                    $updatePasswordQuery = getDatabase()->prepare("UPDATE Users SET Password = :pw WHERE UserID = :uid");
                    $updatePasswordQuery->bindValue(':pw', $passwordHash);
                    $updatePasswordQuery->bindValue(':uid', getUserID());
                    $updatePasswordQueryResult = $updatePasswordQuery->execute();
                    if ($updatePasswordQueryResult) {
                        //success
                        $_SESSION['passwordHash'] = $passwordHash; //update session variable
                        $htmlOut .= '<h3>Password Reset Successfully</h3>';
                    } else {
                        $htmlOut .= '<h3>Sorry, we couldn\'t reset your password at this time, please try again later</h3>';
                    }
                } else {
                    $htmlOut .= '<h3>Invalid Password Format</h3>';
                }

            }

        }

    } else {
        $htmlOut .= resetPasswordForm();
    }

} else {
    $htmlOut .= forgotPasswordForm();
}

echo pageTop();
echo $htmlOut;
echo pageBottom();