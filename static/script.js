
document.addEventListener("submit", function (event) {
    const message = event.target.getAttribute("data-confirm");

    if (message && !window.confirm(message)) {
        event.preventDefault();
    }
});