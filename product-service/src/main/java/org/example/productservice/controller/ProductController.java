package org.example.productservice.controller;

import org.example.productservice.dto.Product;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    private final ConcurrentHashMap<Long, Product> products = new ConcurrentHashMap<>();
    private final AtomicLong idCounter = new AtomicLong(1);

    public ProductController() {
        // Initialize with sample products
        products.put(1L, new Product(1L, "Laptop", "High performance laptop", 999.99));
        products.put(2L, new Product(2L, "Phone", "Smartphone with great camera", 699.99));
        products.put(3L, new Product(3L, "Tablet", "Portable tablet device", 299.99));
    }

    @GetMapping
    @PreAuthorize("isAuthenticated()")
    public List<Product> getAllProducts() {
        return new ArrayList<>(products.values());
    }

    @GetMapping("/{id}")
    @PreAuthorize("isAuthenticated()")
    public Product getProductById(@PathVariable Long id) {
        return products.get(id);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public String deleteProduct(@PathVariable Long id) {
        if (products.remove(id) != null) {
            return "Product deleted successfully";
        }
        return "Product not found";
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public Product createProduct(@RequestBody Product product) {
        Long id = idCounter.getAndIncrement();
        Product newProduct = new Product(id, product.getName(), product.getDescription(), product.getPrice());
        products.put(id, newProduct);
        return newProduct;
    }
}