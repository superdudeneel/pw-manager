
document.getElementById("loginForm").addEventListener("submit", async function (e) {
    e.preventDefault(); // prevent default form submission

    const formData = new FormData(this);
    const data = {
        username: formData.get("username"),
        password: formData.get("password")
    };

    try {
        const response = await fetch("/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data)
        });

        // If backend redirects (like with res.redirect), fetch won't follow it in JS
        const result = await response.json();

        if (result.success === false) {
          Swal.fire({
            title: 'Oops...',
            text: result.message,
            icon: 'error',
            confirmButtonText: 'Try Again',
            customClass: {
              confirmButton: 'my-confirm-button',
            },
            buttonsStyling: false,
            showCloseButton: true
          });
                                
        } else {
            Swal.fire({
              title: 'Success',
              text: 'Login successful',
              icon: 'success',
              confirmButtonText: 'OK',
              timer: 1300,
              customClass: {
                confirmButton: 'my-confirm-button',
              },
            }).then(()=>{
              window.location.href = result.redirect;
            })
            // Redirect manually if login is successful
            
        }
    } catch (err) {
        Swal.fire({
            title: 'Error',
            text: 'Something went wrong. Try again.',
            icon: 'error'
        });
    }
});
