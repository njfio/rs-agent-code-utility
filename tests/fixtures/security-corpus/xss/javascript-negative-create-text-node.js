function render(element, userInput) {
  const textNode = document.createTextNode(userInput);
  element.replaceChildren(textNode);
}
