<?php
set_include_path('/backend-directory');
include('helper.php');

checkSession();
enableImageUpload();

function requestEvalForm(): string
{
    return '
    <form class="mb-4 ml-5 mr-5" action="requestevaluation.php" method="post" enctype="multipart/form-data">
    <h4>New Listing</h4>
        <div class="form-group p-1">
            <label for="comments">Comments  <small>(Required) Maximum 500 Characters</small></label>
            <textarea class="form-control" name="comments" required id="comments" rows="4" placeholder="Description of my item, size, weight, colour, origin, etc."></textarea>
        </div>
        <div class="form-group p-1">
            <label for="phoneOrEmail">Would you prefer to be contacted via Phone or Email?</label>
            <div class="form-check">
                <input class="form-check-input" type="radio" name="phoneOrEmail" id="phone" value="phone">
                <label class="form-check-label" for="phone">Phone</label>
            </div>
            <div class="form-check">
                <input class="form-check-input" type="radio" name="phoneOrEmail" id="email" value="email" checked>
                <label class="form-check-label" for="email">Email</label>
            </div>
        </div>
        <div class="form-group p-1">
            <input type="file" name="image" accept="image/png, image/jpeg, image/jpg, image/gif"/>
        </div>
        <button class="btn btn-primary m-1" type="submit" name="submit">Submit Listing for Evaluation</button>
    </form>    
    ';
}

$htmlOut = ''; //variable to store the html we're going to output all at once to avoid outputting before we can send different headers (for redirects)

if (isUserSignedIn()) {
    if (isset($_POST['submit'])) {
        //form has been submitted
        $comments = sanitise($_POST['comments']);
        $phoneOrEmail = sanitise($_POST['phoneOrEmail']);

        if (strlen($comments) > 500) {
            $comments = substr($comments, 0, 500); //truncate comments to 500 chars if too large
        }

        //set radios to boolean
        if ($phoneOrEmail === 'phone') {
            $phoneOrEmail = 0;
        } else if ($phoneOrEmail === 'email') {
            $phoneOrEmail = 1;
        } else {
            //this shouldn't be possible - default to email
            $phoneOrEmail = 1;
        }

        //image handling
        $imageFileName = '';
        if (isset($_FILES['image'])) { //if user uploaded an image
            $fileName = $_FILES['image']['name'];
            $fileSize = $_FILES['image']['size'];
            $fileTempName = $_FILES['image']['tmp_name'];
            $fileType = $_FILES['image']['type'];
            $fileNameSplit = explode('.',$_FILES['image']['name']);
            $fileExtension = strtolower(end($fileNameSplit));

            $permittedExtensions = array('jpeg','jpg','png', 'gif');

            $correctExtensionBool = in_array($fileExtension, $permittedExtensions);
            $correctSizeBool = $fileSize <= 10485760; //if less than or equal to 10MB (in binary)
            if ($correctExtensionBool && $correctSizeBool) {
                //on success, save it
                $imageFileName = uniqid().'.'.$fileExtension;
                move_uploaded_file($fileTempName, __DIR__."/images/".$imageFileName); //give it a unique name based on the time
                $htmlOut .= "<h4>Image Uploaded Successfully</h4>";
            } else {//else ignore it and let the temporary file get automatically deleted, and tell the user
                $htmlOut .= "<h4>Notice: File must be a jpeg, png or gif, and less than 10MB!</h4>";
            }
        }

        $db = getDatabase();
        $newListingQuery = $db->prepare("INSERT INTO 'Listings' ('UserID', 'Comments', 'PhoneOrEmail', 'ImageName') 
        VALUES (:uid, :cmts, :poe, :img)");
        $newListingQuery->bindValue(':uid', getUserID());
        $newListingQuery->bindValue(':cmts', $comments);
        $newListingQuery->bindValue(':poe', $phoneOrEmail);
        $newListingQuery->bindValue('img', $imageFileName);

        $newListingQueryResult = $newListingQuery->execute();
        if ($newListingQueryResult) {
            $htmlOut .= "<h3>Listing completed successfully.<br><a href='home.php'>Homepage</a> Redirecting in 5 seconds...</h3>";
            header("refresh:5;url=home.php"); //redirect user back home in 5 seconds
        } else {
            $htmlOut .= "<h2>Error: Failed to complete listing, please try again later.</h2>";
        }
        unset($_POST['submit']); //avoid resubmissions
    } else {
        $htmlOut .= requestEvalForm();
    }
} else {
    $htmlOut .= "<h1>Please make sure you're signed in to view this page.</h1>";
}

echo pageTop();
echo $htmlOut;
echo pageBottom();
