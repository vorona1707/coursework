
function removeFromCart(cartItemID) {
    fetch(`/cart/remove`, {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body: `cart_item_id=${cartItemID}`,
    }).then(() => {
        window.location.reload();
    });
}