// TODO: Add back the commented out classnames
// No this doesn't have anything to do with stacks
const pushHamburgerMenu = () => {
    document.querySelector ("nav#hamburger-menu").classList.add ("show");
    // document.querySelector ("div.fade-layer").classList.toggle ("show");

    // Stop the scrolling of the webpage below
    // document.querySelector ("body").classList.toggle ("stop-scroll");
}

// No I can't use toggle, it gets activated again when the menu scrolls away from the
// mouse in that case
const popHamburgerMenu = () => {
    document.querySelector ("nav#hamburger-menu").classList.remove ("show");
    // document.querySelector ("div.fade-layer").classList.toggle ("show");

    // Stop the scrolling of the webpage below
    // document.querySelector ("body").classList.toggle ("stop-scroll");
}

// OPEN MENU: -------
// If the hamburger button is clicked
document.getElementById ("hamburger-button").addEventListener ("click", pushHamburgerMenu);
// If the pointer is dragged to the side
document.getElementById ("hamburger-menu-hover-detect").addEventListener ("pointerenter", pushHamburgerMenu);

// CLOSE MENU: -----------
// If the pointer leaves the menu
document.getElementById ("hamburger-menu").addEventListener ("pointerleave", popHamburgerMenu);
// If the menu is clicked
document.getElementById ("hamburger-menu").addEventListener ("click", popHamburgerMenu);
