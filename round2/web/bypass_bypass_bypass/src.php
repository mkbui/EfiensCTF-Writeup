<?php
ini_set('display_errors', 'on');
ini_set('error_reporting', E_ALL ^ E_DEPRECATED);

if (isset($_GET['debug'])) highlight_file(__FILE__);
if (isset($_POST['code']) && is_string($_POST['code'])) {
    if (preg_match('/^.*({|\~|\$|\n|\r|\=)/im', $_POST['code'])) {
        die("We were hacked by this stuff. So, no more cheating!");
    }
    $code = substr($_POST['code'], 0, 25);
} else {
    $code = "print('Hi Efiens!');";
}
?>

<!DOCTYPE html>
<html>

<head>
    <title>bypas-bypass-bypass</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.16.0/umd/popper.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</head>
<!-- debug mode will be your friend -->

<body>
    <style>
        html,
        body {
            height: 100%;
        }

        #cover {
            background: #222 url('./background.jpg') center center no-repeat;
            background-size: cover;
            color: white;
            height: 100%;
            text-align: center;
            display: flex;
            align-items: center;
        }

        #cover-caption {
            width: 100%;
        }
    </style>
    <section id="cover">
        <div id="cover-caption">
            <div id="container" class="container">
                <div class="row">
                    <div class="col-sm-10 offset-sm-1 text-center">
                        <h1 class="display-3" style="margin-bottom:30px">bypass-bypass-bypass</h1>
                        <p>We made PHP executing service where only allow <strong>echo, print, strlen, strcmp, strncmp</strong>.
                            Oh and you're limited to 25 chars only. Try it out!</p>
                        <div class="info-form">
                            <form action="" method="POST" class="form-inline justify-content-center">
                                <div class="form-group">
                                    <label class="sr-only">Code</label>
                                    <input value="<?php echo htmlspecialchars($code); ?>" required maxlength=25 name="code" type="text" class="form-control" placeholder="jane.doe@example.com">
                                </div>
                                <button type="submit" class="btn btn-success ">Execute!</button>
                            </form>
                        </div>
                        <br>
                    </div>
                </div>
            </div>
            <div class="container">

                <?php

                /* lets allow some secure funcs here (former filter) */
                $funcs_internal = get_defined_functions()['internal'];
                /* ... but no more class for you */
                $classes = get_declared_classes();
                unset($funcs_internal[array_search('strlen', $funcs_internal)]);
                unset($funcs_internal[array_search('print', $funcs_internal)]);
                unset($funcs_internal[array_search('strcmp', $funcs_internal)]);
                unset($funcs_internal[array_search('strncmp', $funcs_internal)]);

                $funcs_extra = array('eval', 'include', 'require', 'function');
                $funny_chars = array('\.', '\+', '-', '\*', '"', '`', '\[', '\]');
                $variables = array('_GET', '_POST', '_COOKIE', '_REQUEST', '_SERVER', '_FILES', '_ENV', 'HTTP_ENV_VARS', '_SESSION', 'GLOBALS');

                $blacklist = array_merge($funcs_internal, $funcs_extra, $funny_chars, $variables, $classes);

                $insecure = false;
                foreach ($blacklist as $blacklisted) {
                    if (preg_match('/' . $blacklisted . '/im', $code)) {
                        $insecure = true;
                        break;
                    }
                }
                if ($insecure) {
                    if (!isset($message)) {
                        $message = 'Insecure code detected!';
                        echo ('<div class="alert alert-danger">' . $message . '</div>');
                    }
                } else {
                    echo ('<div class="alert alert-success">');
                    eval($code);
                    echo ('</div>');
                }
                ?>
            </div>
        </div>
        </div>
    </section>
</body>

</html>