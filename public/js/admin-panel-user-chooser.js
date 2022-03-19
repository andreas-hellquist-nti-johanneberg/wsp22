const selectElement = document.getElementById ("username-select");

selectElement.addEventListener ("change", (event) => {
    const targetLink = document.getElementById ("user-edit-link");
    let value = event.target.value;
    if (value == "Välj en användare") {
        targetLink.href = "#";
    }
    else {
        targetLink.href = `/users/${value}/edit`
    }
});
