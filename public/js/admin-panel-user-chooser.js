const selectElement = document.getElementById ("username-select");

selectElement.addEventListener ("change", (event) => {
    const targetLinkView = document.getElementById ("user-view-link");
    const targetLinkEdit = document.getElementById ("user-edit-link");
    let value = event.target.value;

    if (value == "Välj en användare") {
        targetLinkView.href = "#";
        targetLinkEdit.href = "#";
    }
    else {
        targetLinkView.href = `/users/profile/${value}`
        targetLinkEdit.href = `/users/${value}/edit`
    }
});
