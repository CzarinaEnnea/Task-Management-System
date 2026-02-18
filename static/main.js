const showPassword = document.querySelector('#show-password')

showPassword.addEventListener('click', () => {
    var x = document.querySelector('#password')
    x.type = showPassword.checked ? "text" : "password";
})