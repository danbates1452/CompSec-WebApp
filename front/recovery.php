<?php
set_include_path('/home/danbates/uni-compsec-back/');
include('helper.php');

checkSession();
$htmlOut = ''; //variable to store the html we're going to output all at once to avoid outputting before we can send different headers (for redirects)

function dashboard(): string
{
    //generates the main recovery/account security page, filling in variables from the db where possible
    $dashboard = changePasswordForm().'<hr>'; //no variables should fill in change password's form

    $attributesQuery = getDatabase()->prepare("SELECT * FROM Users where UserId = ?");
    $attributesQuery->bindValue(1, getUserID());
    $attributesQueryResult = $attributesQuery->execute();
    $userAttributesArray = $attributesQueryResult->fetchArray(SQLITE3_ASSOC);
    if ($userAttributesArray) {
        $dashboard .= securityQuestionsForm(
            array($userAttributesArray['Q1'], $userAttributesArray['Q2'], $userAttributesArray['Q3']),
            array($userAttributesArray['A1'], $userAttributesArray['A2'], $userAttributesArray['A3'])
            ).'<hr>';
        $dashboard .= recoveryCodesForm(json_decode($userAttributesArray['RecoveryCodes'])).'<hr>';
        $dashboard .= recoveryEmailForm($userAttributesArray['RecoveryEmail']).'<hr>';
    } else {
        $dashboard .= securityQuestionsForm().'<hr>'.recoveryCodesForm().'<hr>'.recoveryEmailForm(); //no fill
    }

    return $dashboard;
}

function changePasswordForm(): string
{
    return '
    <form action="recovery.php" method="post">
        <div class="form-group p-1">
            <h4>Change Password</h4>
            <label for="oldPassword">Current Password</label>
            <input class="form-control" name="oldPassword" required id="oldPassword" type="text" placeholder="Current Password" maxlength="30" size="30">
            <label for="newPassword">Replacement Password</label>
            <input class="form-control" name="newPassword" required id="newPassword" type="text" placeholder="Replacement Password" pattern="'.getPasswordRegexJS().'" maxlength="30" size="30">
            <button class="btn btn-primary m-1" type="submit" name="submitChangePassword">Submit Password Change</button>
        </div>
    </form>
    ';
}

function securityQuestionsForm($questions = [], $answers = []): string
{
    $form = '<form action="recovery.php" method="post"><div class="form-group p-1"><h4>Security Questions</h4><p>(Write these down before you submit!)</p>';

    for ($i = 1; $i <= 3; $i++) {
        $form .= '<select class="form-select" name="question'.$i.'">';
        $form .= '<option>Select a question</option>'; //default value

        foreach (getSecurityQuestions() as $key => $value) {
            $form.='<span>'.$key.' - '.$questions[$i-1].'</span>';
            if (isset($questions[$i-1]) && $questions[$i-1] === $key) {
                $selected = ' selected';
            } else {
                $selected = '';
            }
            $form .= '<option value="'.$key.'"'.$selected.'>'.$value.'</option>';
        }
        $form .= '</select>';
        $answer = $answers[$i - 1] ?? 'Answer';
        $form .= '<input class="form-control" name="answer'.$i.'" required id="answer'.$i.'" type="text" placeholder="'.$answer.'" size="30" maxlength="30"><br>';
    }
    $form.= '<button class="btn btn-primary m-1" type="submit" name="submitSecurityQuestions">Submit Security Questions</button></div></form>';
    return $form;
}

function recoveryCodesForm($codes = []): string
{
    $form = '<form action="recovery.php" method="post"><div class="form-group p-1"><h4>Recovery Codes</h4><p>Can be used once each to login without your password (we recommend changing your password after doing that!)</p>';

    for ($i = 0;$i < 6;$i++) {
        $code = $codes[$i] ?? 'Not set'; //if there is a code at this index
        $form .= '<label for="'.($i+1).'">'.($i+1).'</label>';
        $form .= '<input class="form-control" name="'.($i+1).'" placeholder="'.$code.'" size="'.strlen($code).'" readonly/>';
    }
    $form.= '<button class="btn btn-primary m-1" type="submit" name="getRecoveryCodes">Get New Recovery Codes</button>';
    $form .= '</div></form>';
    return $form;
}

function recoveryEmailForm($recoveryEmail = 'Not Set'): string
{
    return '
        <form action="recovery.php" method="post">
            <div class="form-group p-1">
                <h4>Recovery Email Address</h4><label for="recoveryEmail">Another address you trust that can be used to restore your account</label>
                <input class="form-control" name="recoveryEmail" required id="emailAddress" type="email" placeholder="'.$recoveryEmail.'"/>
                <button class="btn btn-primary m-1" type="submit" name="setRecoveryEmail">Set Recovery Email</button>
            </div>
        </form>
    ';
}

function doPasswordChange($old, $new): String
{
    if ($old === $new) {
        return 'Old and New Passwords are the same';
    }

    $database = getDatabase();

    $getStoredPasswordQuery = $database->prepare('SELECT Password FROM Users Where UserID = ?');
    $getStoredPasswordQuery->bindValue(1, getUserID());
    $getStoredPasswordQueryResult = $getStoredPasswordQuery->execute();
    if (!$getStoredPasswordQueryResult) return "We couldn't retrieve your password, please try again later";
    $storedPassword = $getStoredPasswordQueryResult->fetchArray(SQLITE3_ASSOC)['Password'];

    if (password_verify($old, $storedPassword)) {
        //old is what they say it is
        //then update it and let them know
        $newHash = password_hash($new, getHashingAlgo());

        $setNewPasswordQuery = $database->prepare('UPDATE Users SET Password = :pw WHERE UserID = :uid');
        $setNewPasswordQuery->bindValue(':pw', $newHash);
        $setNewPasswordQuery->bindValue(':uid', getUserID());
        $setNewPasswordQueryResult = $setNewPasswordQuery->execute();
        if ($setNewPasswordQueryResult) {
            if (isset($_SESSION['passwordHash'])) $_SESSION['passwordHash'] = $newHash;
            return "Password updated successfully, don't forget your new one!";
        } else {
            return "We couldn't set your new password, please try again later";
        }
    } else if (password_verify($new, $storedPassword)) {
        //new is what's stored
        return "Password already set to new password";
    }
    return "Sorry, we had an issue when trying to update your password and it has not been updated. Please try again later";
}

function handleSecurityQuestions($q1, $q2, $q3, $a1, $a2, $a3): string
{
    $questions = array((int)$q1, (int)$q2, (int)$q3);
    $answers = array($a1, $a2, $a3);
    if (count(array_unique($questions)) < count($questions)) {
        return 'Selected Security Questions must be unique, please choose a different question.';
    }
    if (count(array_unique($answers)) < count($answers)) {
        return 'Security Question Answers must be unique, please give a proper answer or change a question.';
    }
    $questionCodesRange = range(1, 10);
    if (in_array($q1, $questionCodesRange) && in_array($q2, $questionCodesRange) && in_array($q3, $questionCodesRange))
    {
        //if question codes are valid
        if (is_string($a1) && is_string($a2) && is_string($a3) && strlen($a1) < 30 && strlen($a2) < 30 && strlen($a3) < 30) {
            //if answers are valid
            //enter into database
            $updateSecurityQuestionsQuery = getDatabase()->prepare("UPDATE Users SET Q1 = :q1, Q2 = :q2, Q3 = :q3, A1 = :a1, A2 = :a2, A3 = :a3 WHERE UserID = :uid");
            $updateSecurityQuestionsQuery->bindValue(':q1', $q1);
            $updateSecurityQuestionsQuery->bindValue(':q2', $q2);
            $updateSecurityQuestionsQuery->bindValue(':q3', $q3);
            $updateSecurityQuestionsQuery->bindValue(':a1', $a1);
            $updateSecurityQuestionsQuery->bindValue(':a2', $a2);
            $updateSecurityQuestionsQuery->bindValue(':a3', $a3);
            $updateSecurityQuestionsQuery->bindValue(':uid', getUserID());

            $updateSecurityQuestionsQueryResult = $updateSecurityQuestionsQuery->execute();
            if ($updateSecurityQuestionsQueryResult) {
                return 'Security Questions Updated Successfully';
            } else {
                return 'We were\'nt able to update your security questions at this time, please try again later';
            }
        } else {
            return 'Please enter valid answers (below 30 characters)';
        }

    } else {
        return 'Please select a valid question.';
    }



}

function resetRecoveryCodes(): string
{
    //just create and push to db new recovery codes, dashboard() will update what the user sees from the db
    $fail = 'We couldn\'t generate new Recovery Codes for you just now, please try again later.';

    $userid = getUserID();
    if (!$userid) return $fail; //if we can't get userid then don't go any further

    $recoveryCodesArray = generateRecoveryCodes();
    $recoveryCodesJson = json_encode($recoveryCodesArray);

    $updateRecoveryCodesQuery = getDatabase()->prepare("UPDATE Users SET RecoveryCodes = :rc WHERE UserID = :uid");
    $updateRecoveryCodesQuery->bindValue(':rc', $recoveryCodesJson);
    $updateRecoveryCodesQuery->bindValue(':uid', $userid);
    $updateRecoveryCodesQueryResult = $updateRecoveryCodesQuery->execute();
    if ($updateRecoveryCodesQueryResult) { //success
        return 'Successfully generated new Recovery Codes, make sure to write them down!';
    } else { //failure
        return $fail;
    }
}

function setRecoveryEmail($newRecoveryEmail): string
{
    $fail = 'We couldn\'t update your recovery email address, please try again later.';
    $userid = getUserID();
    if (!$userid) return $fail; //if we can't get userid then don't go any further

    if (filter_var($newRecoveryEmail, FILTER_VALIDATE_EMAIL)) {
        $updateRecoveryEmailQuery = getDatabase()->prepare("UPDATE Users SET RecoveryEmail = :re WHERE UserID = :uid");
        $updateRecoveryEmailQuery->bindValue(':re', $newRecoveryEmail);
        $updateRecoveryEmailQuery->bindValue(':uid', $userid);
        $updateRecoveryEmailQueryResult = $updateRecoveryEmailQuery->execute();
        if ($updateRecoveryEmailQueryResult) { //success
            return 'Successfully generated new Recovery Codes, make sure to write them down!';
        } else { //failure
            return $fail;
        }
    } else {
        return 'Please enter a valid email.';
    }

}

function wrapAlert($message): string
{
    return '<h3 class="alert alert-warning">'.$message.'</h3>';
}

if (isUserSignedIn()) {
    //only one of these should appear at once as the user interacts with each form
    if (isset($_POST['submitChangePassword'])) $htmlOut .= wrapAlert(doPasswordChange($_POST['oldPassword'], $_POST['newPassword']));
    if (isset($_POST['submitSecurityQuestions'])) {
        $htmlOut .= wrapAlert(handleSecurityQuestions(
            sanitise($_POST['question1']), sanitise($_POST['question2']), sanitise($_POST['question3']), //sanitised just in case
            sanitise($_POST['answer1']), sanitise($_POST['answer2']), sanitise($_POST['answer3'] //actually need sanitisation
        )));
    }
    if (isset($_POST['getRecoveryCodes'])) $htmlOut .= wrapAlert(resetRecoveryCodes());
    if (isset($_POST['setRecoveryEmail'])) $htmlOut .= wrapAlert(setRecoveryEmail(sanitise($_POST['recoveryEmail'])));
    unset($_POST['submitChangePassword'], $_POST['submitSecurityQuestions'], $_POST['getRecoveryCodes'], $_POST['setRecoveryEmail']); //avoid resubmissions
    $htmlOut .= dashboard(); //generate page after any updates
} else {
    //if user not signed in: email entry box to recover password ('Forgot Password?')
    header('location:forgotPassword.php'); //redirect to relevant page
}

echo pageTop();
echo '<div class="mb-4 ml-3 mr-3">'; //add a div to center all the forms
echo $htmlOut;
echo '</div>';
echo pageBottom();