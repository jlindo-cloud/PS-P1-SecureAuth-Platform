/*
 * Muestra solo los campos del método de pago elegido.
 *
 * Es una ayuda de interfaz, no un control de seguridad: el
 * servidor valida el método, el proveedor y los campos
 * correspondientes en app/store.py. Ocultar un campo en el
 * navegador no impide enviarlo, por eso la validación real
 * vive en el backend.
 */
(function () {
  "use strict";

  var metodo = document.getElementById("payment_method");
  var proveedor = document.getElementById("provider");

  if (!metodo || !proveedor) {
    return;
  }

  var bloques = document.querySelectorAll("fieldset[data-metodo]");
  var grupos = proveedor.querySelectorAll("optgroup[data-metodo]");

  function aplicar() {
    var elegido = metodo.value;

    // Campos: solo el bloque del método elegido queda visible
    // y con sus controles habilitados.
    bloques.forEach(function (bloque) {
      var activo = bloque.dataset.metodo === elegido;

      bloque.hidden = !activo;

      bloque.querySelectorAll("input").forEach(function (campo) {
        campo.disabled = !activo;

        if (!activo) {
          campo.value = "";
        }
      });
    });

    // Proveedores: se deshabilita el grupo que no corresponde
    // y, si el seleccionado dejó de ser válido, se pasa al
    // primero disponible.
    var valido = false;

    grupos.forEach(function (grupo) {
      var activo = grupo.dataset.metodo === elegido;

      grupo.disabled = !activo;
      grupo.hidden = !activo;

      if (activo) {
        grupo.querySelectorAll("option").forEach(function (op) {
          if (op.value === proveedor.value) {
            valido = true;
          }
        });
      }
    });

    if (!valido) {
      var primera = proveedor.querySelector(
        'optgroup[data-metodo="' + elegido + '"] option'
      );

      if (primera) {
        proveedor.value = primera.value;
      }
    }
  }

  metodo.addEventListener("change", aplicar);
  aplicar();
})();
