// filepath: c:\SIT\Y2T3\ICT2216\Lab\lab_quiz\src\public\script.js
document.addEventListener('DOMContentLoaded', function() {
    // Check if we're on the search page (has searchForm)
    const searchForm = document.getElementById('searchForm');
    if (searchForm) {
        handleSearchPage();
    }
    
    // Check if we're on the results page (has searchDisplay)
    const searchDisplay = document.getElementById('searchDisplay');
    if (searchDisplay) {
        handleResultsPage();
    }
});

function handleSearchPage() {
    const form = document.getElementById('searchForm');
    const searchInput = document.getElementById('searchTerm');
    
    form.addEventListener('submit', function(event) {
        event.preventDefault();
        
        const searchTerm = searchInput.value.trim();
        
        if (!searchTerm) {
            showError(['Search term is required']);
            return;
        }

        // Clear any existing errors
        clearErrors();
        
        // Send search term to server for validation
        fetch('/search', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ searchTerm: searchTerm })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Input is valid, redirect to results page
                window.location.href = `/results?search=${encodeURIComponent(data.sanitizedTerm)}`;
            } else {
                // Show validation errors and clear input
                showError(data.errors);
                searchInput.value = '';
                searchInput.focus();
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showError(['An error occurred. Please try again.']);
            searchInput.value = '';
        });
    });

    function showError(errors) {
        clearErrors();
        
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error';
        
        if (errors.length === 1) {
            errorDiv.textContent = errors[0];
        } else {
            const ul = document.createElement('ul');
            errors.forEach(error => {
                const li = document.createElement('li');
                li.textContent = error;
                ul.appendChild(li);
            });
            errorDiv.appendChild(ul);
        }
        
        form.insertBefore(errorDiv, form.firstChild);
    }

    function clearErrors() {
        const existingError = form.querySelector('.error');
        if (existingError) {
            existingError.remove();
        }
    }
}

function handleResultsPage() {
    // Get search term from URL params
    const urlParams = new URLSearchParams(window.location.search);
    const searchTerm = urlParams.get('search');
    
    if (searchTerm) {
        // Display the search term (already sanitized by server)
        document.getElementById('searchDisplay').textContent = searchTerm;
    } else {
        // Redirect to home if no search term
        window.location.href = '/';
    }

    // Handle back button
    document.getElementById('backBtn').addEventListener('click', function() {
        window.location.href = '/';
    });
}