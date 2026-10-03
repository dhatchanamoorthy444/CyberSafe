// CyberSafe Browser Extension — Background Service Worker

// Create context menu on install
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'analyze-link',
    title: 'Analyze with CyberSafe',
    contexts: ['link'],
  });
});

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'analyze-link' && info.linkUrl) {
    // Store the URL and open popup
    chrome.storage.local.set({ pendingURL: info.linkUrl }, () => {
      chrome.action.openPopup();
    });
  }
});

// Handle keyboard shortcut (Ctrl+Shift+Y)
chrome.commands.onCommand.addListener((command) => {
  if (command === '_execute_action') {
    chrome.action.openPopup();
  }
});
