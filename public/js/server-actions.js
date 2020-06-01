const actions = ['start', 'stop', 'restart', 'reset', 'update', 'sync']

function init () {
  document.body.prepend()
}

function serverAction(action) {
  if (!actions.includes(action)) return console.error(new Error('Received unknown action'))
  if (!confirm(`Are you sure you want to update this server to the latest version?`)) return console.log(`Cancelled server action: ${action}`)
  fetch(`/api/server/${window.server.id}/${action}`)
    .then(function(response) {
      return response.json()
    })
    .then(function (response) {

    })
    .catch(function (err) {

    })
}

window.onload=init();