class Rectangle:
    def __init__(self, x1, y1, wi, he):
        self.x1 = x1
        self.y1 = y1
        self.width = wi
        self.height = he


def intersect_algorithm_a(box1: Rectangle, box2: Rectangle) -> bool:
    """A：fine for everything except the plus sign"""
    left1, top1 = box1.x1, box1.y1
    right1, bottom1 = box1.x1 + box1.width, box1.y1 + box1.height
    left2, top2 = box2.x1, box2.y1
    right2, bottom2 = box2.x1 + box2.width, box2.y1 + box2.height

    # box1 的左上顶点在 box2 内（包含左/上边界，不包含右/下边界）
    top_left_inside = (top1 >= top2 and left1 >= left2) and (top1 < bottom2 and left1 < right2)

    # box1 的右上顶点在 box2 内（包含上/右边界的上/右判定与原逻辑等价）
    top_right_inside = (top1 >= top2 and right1 <= right2) and (top1 < bottom2 and right1 > left2)

    if top_left_inside or top_right_inside:
        return True
    return False


def intersect_algorithm_b(box1: Rectangle, box2: Rectangle) -> bool:
    """B: correct answer without reversing"""
    if (((box1.y1 >= box2.y1 and box1.x1 >= box2.x1) and
         (box1.y1 < (box2.y1 + box2.height) and box1.x1 < (box2.x1 + box2.width))) or
        ((box1.y1 >= box2.y1 and box1.x1 + box1.width <= box2.x1 + box2.width) and
         (box1.y1 < (box2.y1 + box2.height) and box1.x1 + box1.width < box2.x1)) or
        ((box1.y1 < box2.y1 and box1.x1 > box2.x1) and
         ((box1.y1 + box1.height) > (box2.y1 + box2.height) and
          (box1.x1 + box1.width) < (box2.x1 + box2.width)))):
        return True
    return False


def intersect_algorithm_c(box1: Rectangle, box2: Rectangle) -> bool:
    """
    correct answer but also any touching [edge/vertex] is considered an overlap  incorrect according to spec
    """
    if (box1.x1 <= (box2.x1 + box2.width) and
        (box1.x1 + box1.width) >= box2.x1 and
        box1.y1 <= (box2.y1 + box2.height) and
        (box1.y1 + box1.height) >= box2.y1):
        return True
    return False


def intersect_algorithm_d(box1: Rectangle, box2: Rectangle) -> bool:
    """
    D: any vertex inside the area of the opposite rectangle is an overlap, 
    and nothing else is only plus sign and identical rectangles fail
    """
    if ((box1.x1 > box2.x1 and box1.x1 < (box2.x1 + box2.width)) or
        (box1.y1 > box2.y1 and box1.y1 < (box2.y1 + box2.height)) or
        ((box1.x1 + box1.width) > box2.x1 and (box1.x1 + box1.width) < (box2.x1 + box2.width)) or
        ((box1.y1 + box1.height) > box2.y1 and (box1.y1 + box1.height) < (box2.y1 + box2.height))):
        return True
    return False


def intersect_algorithm_e(box1: Rectangle, box2: Rectangle) -> bool:
    """E"""
    if (box1.x1 < (box2.x1 + box2.width) and
        (box1.x1 + box1.width) > box2.x1 and
        box1.y1 < (box2.y1 + box2.height) and
        (box1.y1 + box1.height) > box2.y1):
        return True
    return False


def intersect_algorithm_f(box1: Rectangle, box2: Rectangle) -> bool:
    """F"""
    if (((box1.y1 >= box2.y1 and box1.x1 >= box2.x1) and
            (box1.y1 < (box2.y1 + box2.height) and box1.x1 < (box2.x1 + box2.width))) or
        ((box1.y1 >= box2.y1 and box1.x1 + box1.width <= box2.x1 + box2.width) and
            (box1.y1 < (box2.y1 + box2.height) and box1.x1 + box1.width > box2.x1)) or
        ((box1.y1 < box2.y1 and box1.x1 > box2.x1) and
            ((box1.y1 + box1.height) > (box2.y1 + box2.height) and
            (box1.x1 + box1.width) < (box2.x1 + box2.width)))):
        return True
    return False


func_dict = {
    'A': intersect_algorithm_a,
    'B': intersect_algorithm_b,
    'C': intersect_algorithm_c,
    'D': intersect_algorithm_d,
    'E': intersect_algorithm_e,
    'F': intersect_algorithm_f,
}


def check_intersection(box1: Rectangle, box2: Rectangle, alg_id: str) -> bool:
    """统一接口 检查矩形相交"""
    func = func_dict.get(alg_id)
    if not func:
        raise ValueError(f"Unknown algorithm ID: {alg_id}")
    return bool(func(box1, box2) or func(box2, box1))
